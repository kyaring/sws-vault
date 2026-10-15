package api

import (
	"crypto/rand"
	"github.com/kyaring/sws-vault/internal/auth"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestAdminLoginTOTPReplayRejected(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	password := "fake-password-only-123"
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	hash, e := auth.HashPassword(password, salt)
	if e != nil {
		t.Fatal(e)
	}
	totp := []byte("fake totp secret for tests")
	_, e = st.DB.Exec(`INSERT INTO admins(id,password_hash,password_salt,totp_secret,created_at) VALUES(1,?,?,?,?)`, hash, salt, totp, time.Now().UTC().Format(time.RFC3339))
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("GET", "/admin/login", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	re := regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	m := re.FindStringSubmatch(w.Body.String())
	if len(m) != 2 {
		t.Fatal("login csrf missing")
	}
	var csrf *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "sv_login_csrf" {
			csrf = ck
		}
	}
	if csrf == nil {
		t.Fatal("login csrf cookie missing")
	}
	form := url.Values{"csrf": {m[1]}, "password": {password}, "totp": {auth.GenerateTOTP(totp, time.Now())}}
	post := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/admin/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(csrf)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	w = post()
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login failed: %d %s", w.Code, w.Body.String())
	}
	w = post()
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("replayed TOTP accepted: %d", w.Code)
	}
}
