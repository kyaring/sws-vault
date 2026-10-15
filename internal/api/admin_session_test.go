package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAdminIdleSessionExpires(t *testing.T) {
	s, _, _, _ := testServer(t, "secrets:list")
	sessions.Lock()
	sessions.m["expired-session"] = adminSession{csrf: "fake-csrf", created: time.Now().Add(-20 * time.Minute), last: time.Now().Add(-16 * time.Minute)}
	sessions.Unlock()
	r := httptest.NewRequest("GET", "/admin/", nil)
	r.AddCookie(&http.Cookie{Name: "sws_admin", Value: "expired-session"})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/login" {
		t.Fatalf("expired session accepted: %d", w.Code)
	}
}
