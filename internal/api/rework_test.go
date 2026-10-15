package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kyaring/sws-vault/internal/auth"
	"github.com/kyaring/sws-vault/internal/store"
)

func TestResolveRequiresAllowResolveAndNoStore(t *testing.T) {
	s, _, token, _ := testServer(t, "secrets:write,resolve")
	for _, tc := range []struct {
		name  string
		allow bool
	}{{"denied", false}, {"allowed", true}} {
		body := "{\"ns\":\"ns1\",\"label\":\"" + tc.name + "\",\"provider\":\"generic\",\"type\":\"token\",\"value\":\"FAKE-RESOLVE-ONLY\",\"bindings\":{\"allow_resolve\":" + map[bool]string{true: "true", false: "false"}[tc.allow] + "}}"
		code, out := request(t, s, token, http.MethodPost, "/v1/secrets", body)
		if code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", tc.name, code, out)
		}
		var m Metadata
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader("{\"secret\":\"vault:ns1/"+m.ID+"\"}"))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if !tc.allow {
			if w.Code != http.StatusForbidden || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "FAKE-RESOLVE-ONLY") {
				t.Fatalf("allow_resolve=false returned %d or value: %s", w.Code, w.Body.String())
			}
		} else if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), "FAKE-RESOLVE-ONLY") {
			t.Fatalf("resolve response status=%d cache=%q body=%s", w.Code, w.Header().Get("Cache-Control"), w.Body.String())
		}
	}
}

func TestAdminAssetAllowListAndContentTypes(t *testing.T) {
	s, _, _, _ := testServer(t, "secrets:list")
	for _, tc := range []struct {
		path, contentType string
		want              int
	}{{"/admin/assets/admin.css", "css", http.StatusOK}, {"/admin/assets/admin.js", "javascript", http.StatusOK}, {"/admin/assets/assets.go", "", http.StatusNotFound}, {"/admin/assets/x.js", "", http.StatusNotFound}, {"/admin/assets/", "", http.StatusNotFound}} {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s status=%d want=%d", tc.path, w.Code, tc.want)
		}
		if tc.want == http.StatusOK {
			if !strings.Contains(strings.ToLower(w.Header().Get("Content-Type")), tc.contentType) {
				t.Errorf("%s Content-Type=%q want to contain %q", tc.path, w.Header().Get("Content-Type"), tc.contentType)
			}
			if w.Body.Len() == 0 {
				t.Errorf("%s returned an empty body", tc.path)
			}
			if tc.path == "/admin/assets/admin.css" && !strings.Contains(w.Body.String(), ".bar .btn { flex: 1; }") {
				t.Error("admin.css missing equal-width sticky action rule")
			}
		}
	}
}

func TestMemoryTablesCleanupExpiredEntries(t *testing.T) {
	now := time.Now()
	sessions.Lock()
	sessions.m = map[string]adminSession{
		"expired": {created: now.Add(-9 * time.Hour), last: now.Add(-9 * time.Hour)},
		"live":    {created: now.Add(-time.Hour), last: now.Add(-time.Minute)},
	}
	sessions.Unlock()
	rateState.Lock()
	rateState.m = map[string]bucket{"old": {tokens: 1, last: now.Add(-10 * time.Minute)}, "fresh": {tokens: 1, last: now}}
	rateState.Unlock()
	loginAttempts.Lock()
	loginAttempts.m = map[string]loginAttempt{
		"stale":  {failures: 1, last: now.Add(-20 * time.Minute)},
		"locked": {failures: 5, lockedUntil: now.Add(5 * time.Minute), last: now.Add(-20 * time.Minute)},
	}
	loginAttempts.Unlock()
	cleanupMemoryState(now)
	sessions.Lock()
	_, expired := sessions.m["expired"]
	_, live := sessions.m["live"]
	sessions.Unlock()
	if expired || !live {
		t.Fatalf("session cleanup expired=%v live=%v", expired, live)
	}
	rateState.Lock()
	_, old := rateState.m["old"]
	_, fresh := rateState.m["fresh"]
	rateState.Unlock()
	if old || !fresh {
		t.Fatalf("rate cleanup old=%v fresh=%v", old, fresh)
	}
	loginAttempts.Lock()
	_, stale := loginAttempts.m["stale"]
	_, locked := loginAttempts.m["locked"]
	loginAttempts.Unlock()
	if stale || !locked {
		t.Fatalf("login cleanup stale=%v locked=%v", stale, locked)
	}
}

func TestAdminBindingRejectsInvalidHost(t *testing.T) {
	s, _, _, _ := testServer(t, "secrets:list")
	m, err := s.save(SecretRequest{NS: "ns1", Label: "binding-test", Provider: "generic", Type: "token", Value: "FAKE-BINDING-VALUE"}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	sessions.Lock()
	sessions.m["binding-session"] = adminSession{csrf: "fake-csrf", created: time.Now(), last: time.Now()}
	sessions.Unlock()
	form := url.Values{"csrf": {"fake-csrf"}, "hosts": {"https://evil.example/path"}}
	r := httptest.NewRequest(http.MethodPost, "/admin/secrets/"+m.ID+"/bindings", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "sws_admin", Value: "binding-session"})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid binding host accepted: %d %s", w.Code, w.Body.String())
	}
}

func TestValidHostBindingRejectsURLAndMalformedPorts(t *testing.T) {
	for _, host := range []string{"example.test", "example.test:443", "[::1]", "example.test."} {
		if !validHostBinding(host) {
			t.Errorf("valid host rejected: %q", host)
		}
	}
	for _, host := range []string{"https://example.test/path", "example.test/path", "user@example.test", "example.test:99999", "example.test?x=1", "example.test%2f.evil"} {
		if validHostBinding(host) {
			t.Errorf("invalid host accepted: %q", host)
		}
	}
}

func TestUsernameMaskedInMetadataListPanelAndMCP(t *testing.T) {
	s, _, token, _ := testServer(t, "secrets:write,secrets:list")
	sentinel := "SENTINEL-USER-9f2"
	body := "{\"ns\":\"ns1\",\"label\":\"username-test\",\"provider\":\"generic\",\"type\":\"login\",\"value\":\"FAKE-LOGIN-VALUE\",\"username\":\"" + sentinel + "\",\"bindings\":{\"username\":\"" + sentinel + "\"}}"
	code, out := request(t, s, token, http.MethodPost, "/v1/secrets", body)
	if code != 201 || strings.Contains(out, sentinel) {
		t.Fatalf("create metadata leaked username: %d %s", code, out)
	}
	code, out = request(t, s, token, http.MethodGet, "/v1/secrets?ns=ns1", "")
	if code != 200 || strings.Contains(out, sentinel) {
		t.Fatalf("list leaked username: %d %s", code, out)
	}
	sessions.Lock()
	sessions.m["username-session"] = adminSession{csrf: "csrf", created: time.Now(), last: time.Now()}
	sessions.Unlock()
	r := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	r.AddCookie(&http.Cookie{Name: "sws_admin", Value: "username-session"})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), sentinel) {
		t.Fatalf("panel leaked username: %d", w.Code)
	}
	mcpBody := "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"vault_list\",\"arguments\":{\"ns\":\"ns1\"}}}"
	code, out = request(t, s, token, http.MethodPost, "/mcp", mcpBody)
	if code != 200 || strings.Contains(out, sentinel) {
		t.Fatalf("MCP leaked username: %d %s", code, out)
	}
	var stored string
	if err := s.S.DB.QueryRow("SELECT bindings FROM secrets WHERE label='username-test'").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stored, sentinel) {
		t.Fatal("raw username was not retained for provider injection")
	}
}

func TestClientTokenHashConfirmationIsConstantTime(t *testing.T) {
	a := []byte("fake-token-hash-a")
	b := []byte("fake-token-hash-a")
	c := []byte("fake-token-hash-b")
	if !constantTimeHashEqual(a, b) {
		t.Fatal("equal hashes did not match")
	}
	if constantTimeHashEqual(a, c) {
		t.Fatal("different hashes matched")
	}
	old := constantTimeHashEqualFn
	calls := 0
	constantTimeHashEqualFn = func(candidate, stored []byte) bool {
		calls++
		return constantTimeHashEqual(candidate, stored)
	}
	defer func() { constantTimeHashEqualFn = old }()
	s, _, token, _ := testServer(t, "secrets:list")
	code, _ := request(t, s, token, http.MethodGet, "/v1/secrets?ns=ns1", "")
	if code != http.StatusOK {
		t.Fatalf("authenticated list status=%d", code)
	}
	if calls != 1 {
		t.Fatalf("authenticated request called constant-time hash seam %d times, want 1", calls)
	}
}

func prepareAdminLogin(t *testing.T, s *Server, st *store.Store) (string, string, string, *http.Cookie) {
	t.Helper()
	password := "fake-admin-password-2026"
	salt := []byte("fake-salt-123456")
	hash, err := auth.HashPassword(password, salt)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("fake totp secret for tests")
	_, err = st.DB.Exec(`INSERT INTO admins(id,password_hash,password_salt,totp_secret,created_at) VALUES(1,?,?,?,?)`, hash, salt, secret, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	s.C.PublicBaseURL = "https://vault.example.test"
	r := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if len(m) != 2 {
		t.Fatal("login CSRF missing")
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "sv_login_csrf" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("login CSRF cookie missing")
	}
	return password, auth.GenerateTOTP(secret, time.Now()), m[1], cookie
}

func TestAdminCookieAttributesAndAbsoluteTimeout(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	password, totp, csrf, csrfCookie := prepareAdminLogin(t, s, st)
	if !csrfCookie.HttpOnly || csrfCookie.SameSite != http.SameSiteStrictMode || !csrfCookie.Secure {
		t.Fatalf("unsafe login CSRF cookie: %+v", csrfCookie)
	}
	form := url.Values{"csrf": {csrf}, "password": {password}, "totp": {totp}}
	r := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(csrfCookie)
	r.RemoteAddr = "198.51.100.31:1234"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login status=%d body=%s", w.Code, w.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "sws_admin" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil || !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteStrictMode || !sessionCookie.Secure || sessionCookie.MaxAge != 28800 {
		t.Fatalf("unsafe session cookie: %+v", sessionCookie)
	}
	sessions.Lock()
	sess := sessions.m[sessionCookie.Value]
	sess.created = time.Now().Add(-9 * time.Hour)
	sess.last = time.Now()
	sessions.m[sessionCookie.Value] = sess
	sessions.Unlock()
	r = httptest.NewRequest(http.MethodGet, "/admin/", nil)
	r.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/login" {
		t.Fatalf("absolute session timeout not enforced: %d", w.Code)
	}
}

func TestAdminLockoutScopedToSourceIP(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	password, totp, csrf, csrfCookie := prepareAdminLogin(t, s, st)
	now := time.Now()
	loginAttempts.Lock()
	loginAttempts.m["198.51.100.10"] = loginAttempt{failures: 5, lockedUntil: now.Add(15 * time.Minute), last: now}
	loginAttempts.Unlock()
	form := url.Values{"csrf": {csrf}, "password": {password}, "totp": {totp}}
	post := func(ip string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(csrfCookie)
		r.RemoteAddr = ip + ":1234"
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	if w := post("198.51.100.20"); w.Code != http.StatusSeeOther {
		t.Fatalf("unlocked IP could not log in: %d %s", w.Code, w.Body.String())
	}
	if w := post("198.51.100.10"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("locked IP was not blocked: %d", w.Code)
	}
}
