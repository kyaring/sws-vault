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
