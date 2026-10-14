package vaultcrypto

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyringRewrapKeepsOldValueReadable(t *testing.T) {
	d := t.TempDir()
	k1, _ := NewKey()
	if e := os.WriteFile(filepath.Join(d, "master.key"), []byte(base64.RawStdEncoding.EncodeToString(k1)), 0600); e != nil {
		t.Fatal(e)
	}
	r, e := LoadKeyring(d)
	if e != nil {
		t.Fatal(e)
	}
	dek, _ := NewKey()
	aad := []byte("ns/id/dek")
	old, e := r.Wrap(1, dek, aad)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Rotate(d); e != nil {
		t.Fatal(e)
	}
	r2, e := LoadKeyring(d)
	if e != nil {
		t.Fatal(e)
	}
	unwrapped, e := r2.Unwrap(1, old, aad)
	if e != nil {
		t.Fatal(e)
	}
	if string(unwrapped) != string(dek) {
		t.Fatal("old wrapped DEK unreadable after rotation")
	}
	fresh, e := r2.Wrap(r2.Current, dek, aad)
	if e != nil {
		t.Fatal(e)
	}
	got, e := r2.Unwrap(r2.Current, fresh, aad)
	if e != nil || string(got) != string(dek) {
		t.Fatal("new key wrap failed", e)
	}
}

func TestLoadKeyringEnforcesMasterKeyPermissions(t *testing.T) {
	d := t.TempDir()
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(d, "master.key")
	data := []byte(base64.RawStdEncoding.EncodeToString(key) + "\n")
	for _, mode := range []os.FileMode{0644, 0640} {
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKeyringAt(path); err == nil {
			t.Errorf("mode %04o accepted", mode)
		}
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyringAt(path); err != nil {
		t.Fatalf("0600 key rejected: %v", err)
	}
}
