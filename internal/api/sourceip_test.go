package api

import (
	"bytes"
	"github.com/kyaring/sws-vault/internal/config"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

func TestUntrustedForwardedForWarnsOnceAndUsesPeerIP(t *testing.T) {
	previousLogger := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(previousLogger)
	// This test owns the only unconfigured-XFF warning in this package test process.
	untrustedForwardedWarning = sync.Once{}
	defer func() { untrustedForwardedWarning = sync.Once{} }()
	s := &Server{C: config.Config{}, Mux: http.NewServeMux()}
	s.Mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := s.Handler()
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("GET", "/healthz", nil)
		r.RemoteAddr = "192.0.2.44:1234"
		r.Header.Set("X-Forwarded-For", "198.51.100.77")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("health status=%d", w.Code)
		}
		if got := s.sourceIP(r); got != "192.0.2.44" {
			t.Fatalf("untrusted XFF changed peer IP: %s", got)
		}
	}
	if got := strings.Count(logs.String(), "X-Forwarded-For received without SWSV_TRUSTED_PROXY_CIDRS"); got != 1 {
		t.Fatalf("WARN count=%d, want exactly one; logs=%s", got, logs.String())
	}
}
