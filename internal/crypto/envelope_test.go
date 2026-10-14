package vaultcrypto

import "testing"

func TestEnvelopeAADAndTamper(t *testing.T) {
	k, _ := NewKey()
	p := []byte("SENTINEL-VALUE-7f3a9c")
	c, e := Seal(k, p, []byte("ns/id/token"))
	if e != nil {
		t.Fatal(e)
	}
	g, e := Open(k, c, []byte("ns/id/token"))
	if e != nil || string(g) != string(p) {
		t.Fatalf("round trip: %q %v", g, e)
	}
	if _, e = Open(k, c, []byte("other/id/token")); e == nil {
		t.Fatal("AAD mismatch accepted")
	}
	c[len(c)-1] ^= 1
	if _, e = Open(k, c, []byte("ns/id/token")); e == nil {
		t.Fatal("tamper accepted")
	}
}
