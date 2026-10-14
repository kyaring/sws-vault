package store

import (
	"encoding/base64"
	vaultcrypto "github.com/kyaring/sws-vault/internal/crypto"
	"os"
	"path/filepath"
	"testing"
)

func TestRotateKEKRewrapsStoredDEK(t *testing.T) {
	d := t.TempDir()
	k, _ := vaultcrypto.NewKey()
	if e := os.WriteFile(filepath.Join(d, "master.key"), []byte(base64.RawStdEncoding.EncodeToString(k)), 0600); e != nil {
		t.Fatal(e)
	}
	ring, e := vaultcrypto.LoadKeyring(d)
	if e != nil {
		t.Fatal(e)
	}
	s, e := Open(filepath.Join(d, "vault.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	_, e = s.DB.Exec(`INSERT INTO namespaces(id,name,created_at) VALUES('ns','ns','now')`)
	if e != nil {
		t.Fatal(e)
	}
	dek, _ := vaultcrypto.NewKey()
	oldAAD := vaultcrypto.DEKAAD("ns", "secret", 1)
	wrapped, e := ring.Wrap(1, dek, oldAAD)
	if e != nil {
		t.Fatal(e)
	}
	ct, e := vaultcrypto.Seal(dek, []byte("SENTINEL-VALUE-7f3a9c"), vaultcrypto.SecretAAD("ns", "secret", "token", 1))
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.DB.Exec(`INSERT INTO secrets(id,ns,label,provider,type,ciphertext,dek_wrapped,key_version,preview,fingerprint,bindings,created_at,rotated_at) VALUES('secret','ns','label','generic','token',?,?,1,'••••9c','fp','{}','now','now')`, ct, wrapped)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.RotateKEK(ring, d); e != nil {
		t.Fatal(e)
	}
	var newWrapped, newCT []byte
	var version uint32
	if e = s.DB.QueryRow(`SELECT dek_wrapped,ciphertext,key_version FROM secrets WHERE id='secret'`).Scan(&newWrapped, &newCT, &version); e != nil {
		t.Fatal(e)
	}
	aad := vaultcrypto.DEKAAD("ns", "secret", version)
	got, e := ring.Unwrap(version, newWrapped, aad)
	if e != nil || string(got) != string(dek) {
		t.Fatalf("rotated key unreadable: %v", e)
	}
	plain, e := vaultcrypto.Open(got, newCT, vaultcrypto.SecretAAD("ns", "secret", "token", version))
	if e != nil || string(plain) != "SENTINEL-VALUE-7f3a9c" {
		t.Fatalf("secret changed after rotation: %v", e)
	}
}
