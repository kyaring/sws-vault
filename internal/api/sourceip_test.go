package api

import (
	"github.com/kyaring/sws-vault/internal/config"
	"net/http/httptest"
	"testing"
)

func TestForwardedIPOnlyTrustedWhenPeerIsTrusted(t *testing.T) {
	s := &Server{C: config.Config{TrustedProxyCIDRs: []string{"10.0.0.0/8"}}}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.10:443"
	r.Header.Set("X-Forwarded-For", "198.51.100.8")
	if got := s.sourceIP(r); got != "192.0.2.10" {
		t.Fatalf("untrusted peer forwarded header: %s", got)
	}
	r.RemoteAddr = "10.0.0.2:443"
	r.Header.Set("X-Forwarded-For", "198.51.100.8, 10.0.0.3")
	if got := s.sourceIP(r); got != "198.51.100.8" {
		t.Fatalf("trusted proxy chain resolved to %s", got)
	}
}
