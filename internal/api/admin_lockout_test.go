package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestAdminLocksAfterFiveFailures(t *testing.T) {
	s, _, _, _ := testServer(t, "secrets:list")
	r := httptest.NewRequest("GET", "/admin/login", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if len(m) != 2 {
		t.Fatal("csrf missing")
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "sv_login_csrf" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("csrf cookie missing")
	}
	for i := 0; i < 5; i++ {
		form := url.Values{"csrf": {m[1]}, "password": {"fake-password-only"}, "totp": {"000000"}}
		r = httptest.NewRequest("POST", "/admin/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(cookie)
		w = httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("failure %d status %d", i, w.Code)
		}
	}
	form := url.Values{"csrf": {m[1]}, "password": {"fake-password-only"}, "totp": {"000000"}}
	r = httptest.NewRequest("POST", "/admin/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 429 {
		t.Fatalf("sixth attempt not locked: %d", w.Code)
	}
}
