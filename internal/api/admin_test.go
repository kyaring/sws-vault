package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPanelNeverDisplaysSecretAndRequiresCSRF(t *testing.T) {
	s, _, _, _ := testServer(t, "secrets:list,secrets:write")
	sentinel := "SENTINEL-VALUE-7f3a9c"
	m, e := s.save(SecretRequest{NS: "ns1", Label: "test", Provider: "generic", Type: "token", Value: sentinel}, false, "")
	if e != nil {
		t.Fatal(e)
	}
	sessions.Lock()
	sessions.m["fake-session"] = adminSession{csrf: "fake-csrf", created: time.Now(), last: time.Now()}
	sessions.Unlock()
	r := httptest.NewRequest("GET", "/admin/secrets", nil)
	r.AddCookie(&http.Cookie{Name: "sws_admin", Value: "fake-session"})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 || containsSentinel(w.Body.String(), sentinel) {
		t.Fatalf("panel exposed secret or failed: %d", w.Code)
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("security headers missing")
	}
	for _, path := range []string{"/admin/secrets/new", "/admin/projects", "/admin/projects/new", "/admin/projects/ns1/clients/c1", "/admin/audit", "/admin/intents/new", "/admin/secrets/" + m.ID + "/bindings", "/admin/secrets/" + m.ID + "/rotate", "/admin/assets/admin.css"} {
		rr := httptest.NewRequest("GET", path, nil)
		rr.AddCookie(&http.Cookie{Name: "sws_admin", Value: "fake-session"})
		ww := httptest.NewRecorder()
		s.Handler().ServeHTTP(ww, rr)
		if ww.Code != 200 || containsSentinel(ww.Body.String(), sentinel) {
			t.Fatalf("panel page %s leaked sentinel or failed: %d", path, ww.Code)
		}
	}
	r = httptest.NewRequest("POST", "/admin/secrets/new", strings.NewReader("label=x&value=SENTINEL-VALUE-7f3a9c"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "sws_admin", Value: "fake-session"})
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("missing CSRF accepted: %d", w.Code)
	}
}
