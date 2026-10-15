package vaultcrypto

import (
	"bytes"
	"testing"
)

func TestEnvelopeAADAndTamper(t *testing.T) {
	k, e := NewKey()
	if e != nil {
		t.Fatal(e)
	}
	p := []byte("SENTINEL-VALUE-7f3a9c")
	aad := SecretAAD("ns", "id", "token", 1)
	c, e := Seal(k, p, aad)
	if e != nil {
		t.Fatal(e)
	}
	g, e := Open(k, c, aad)
	if e != nil || !bytes.Equal(g, p) {
		t.Fatalf("round trip failed: %v", e)
	}
	if _, e = Open(k, c, SecretAAD("other", "id", "token", 1)); e == nil {
		t.Fatal("namespace AAD mismatch accepted")
	}
	if _, e = Open(k, c, SecretAAD("ns", "id", "token", 2)); e == nil {
		t.Fatal("key-version AAD mismatch accepted")
	}
	c[len(c)-1] ^= 1
	if _, e = Open(k, c, aad); e == nil {
		t.Fatal("tamper accepted")
	}
}
func TestHKDFPurposeSeparation(t *testing.T) {
	master, _ := NewKey()
	a, e := DeriveKey(master, "kek-wrap")
	if e != nil {
		t.Fatal(e)
	}
	b, e := DeriveKey(master, "fingerprint")
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Equal(a, b) {
		t.Fatal("HKDF purpose keys are equal")
	}
}
