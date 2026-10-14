package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/kyaring/sws-vault/internal/api"
	"github.com/kyaring/sws-vault/internal/auth"
	"github.com/kyaring/sws-vault/internal/config"
	vaultcrypto "github.com/kyaring/sws-vault/internal/crypto"
	"github.com/kyaring/sws-vault/internal/store"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func captureIO(t *testing.T, input string, fn func() error) (string, string, error) {
	t.Helper()
	oldIn, oldOut, oldErr := os.Stdin, os.Stdout, os.Stderr
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	_, _ = inW.Write([]byte(input))
	_ = inW.Close()
	os.Stdin = inR
	os.Stdout = outW
	os.Stderr = errW
	e := fn()
	_ = outW.Close()
	_ = errW.Close()
	os.Stdin = oldIn
	os.Stdout = oldOut
	os.Stderr = oldErr
	out, _ := io.ReadAll(outR)
	er, _ := io.ReadAll(errR)
	_ = inR.Close()
	_ = outR.Close()
	_ = errR.Close()
	return string(out), string(er), e
}
func TestLocalSmokeKeygenAdminClientFetchMCP(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("client create is intentionally root-only")
	}
	dir := t.TempDir()
	sentinel := "SENTINEL-VALUE-7f3a9c"
	t.Setenv("SWSV_CONFIG", "")
	t.Setenv("SWSV_DATA_DIR", dir)
	t.Setenv("SWSV_DB_PATH", "")
	t.Setenv("SWSV_MASTER_KEY_PATH", "")
	t.Setenv("SWSV_LISTEN", "127.0.0.1:9531")
	t.Setenv("SWSV_PUBLIC_BASE_URL", "")
	t.Setenv("SWSV_RATE_LIMIT_PER_MINUTE", "60")
	keyPath := filepath.Join(dir, "master.key")
	if e := keygen([]string{"--out", keyPath}); e != nil {
		t.Fatal(e)
	}
	st, e := os.Stat(keyPath)
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("key file mode: %v", e)
	}
	password := "fake-admin-password-SENTINEL-7f3a9c"
	out, initErr, e := captureIO(t, password+"\n"+password+"\n", func() error { return adminInit(false) })
	if e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(out, "otpauth://totp/") {
		t.Fatal("admin init did not emit enrollment URI")
	}
	tokenOut, tokenErr, e := captureIO(t, "", func() error {
		return client([]string{"create", "--ns", "demo", "--name", "smoke", "--scopes", "secrets:list,secrets:write,fetch,resolve,intents:create"})
	})
	if e != nil {
		t.Fatal(e)
	}
	token := strings.TrimSpace(tokenOut)
	if !strings.HasPrefix(token, "swsv_") {
		t.Fatal("client token was not emitted once")
	}
	c, e := config.Load()
	if e != nil {
		t.Fatal(e)
	}
	ring, e := vaultcrypto.LoadKeyringAt(c.MasterKeyPath)
	if e != nil {
		t.Fatal(e)
	}
	stStore, e := store.Open(c.DBPath)
	if e != nil {
		t.Fatal(e)
	}
	defer stStore.Close()
	var totp []byte
	if e = stStore.DB.QueryRow(`SELECT totp_secret FROM admins WHERE id=1`).Scan(&totp); e != nil {
		t.Fatal(e)
	}
	app := api.NewWithKeyring(c, stStore, ring)
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()
	httpClient := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 10 * time.Second}
	get, e := httpClient.Get(srv.URL + "/admin/login")
	if e != nil {
		t.Fatal(e)
	}
	loginHTML, _ := io.ReadAll(get.Body)
	_ = get.Body.Close()
	re := regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	match := re.FindStringSubmatch(string(loginHTML))
	if len(match) != 2 {
		t.Fatal("login csrf missing")
	}
	var loginCSRF *http.Cookie
	for _, ck := range get.Cookies() {
		if ck.Name == "sv_login_csrf" {
			loginCSRF = ck
		}
	}
	if loginCSRF == nil {
		t.Fatal("login csrf cookie missing")
	}
	form := url.Values{"csrf": {match[1]}, "password": {password}, "totp": {auth.GenerateTOTP(totp, time.Now())}}
	req, _ := http.NewRequest("POST", srv.URL+"/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(loginCSRF)
	resp, e := httpClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("admin login failed: %d", resp.StatusCode)
	}
	var session *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == "sws_admin" {
			session = ck
		}
	}
	if session == nil {
		t.Fatal("admin session cookie missing")
	}
	req, _ = http.NewRequest("GET", srv.URL+"/admin/", nil)
	req.AddCookie(session)
	resp, e = httpClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	dash, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	match = re.FindStringSubmatch(string(dash))
	if len(match) != 2 {
		t.Fatal("panel csrf missing")
	}
	received := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("X-Api-Key")
		w.Header().Set("X-Echo", r.Header.Get("X-Api-Key"))
		_, _ = w.Write([]byte(r.Header.Get("X-Api-Key") + " " + base64.StdEncoding.EncodeToString([]byte(sentinel))))
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	port := u.Port()
	headers, _ := json.Marshal(map[string]string{"X-Api-Key": "{v}"})
	panelForm := url.Values{"csrf": {match[1]}, "ns": {"demo"}, "label": {"smoke-fake"}, "provider": {"generic"}, "type": {"token"}, "value": {sentinel}, "hosts": {"127.0.0.1:" + port}, "headers": {string(headers)}, "allow_private": {"on"}, "allow_http": {"on"}, "allow_resolve": {"on"}}
	req, _ = http.NewRequest("POST", srv.URL+"/admin/secrets/new", strings.NewReader(panelForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	resp, e = httpClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("panel write failed: %d", resp.StatusCode)
	}
	var secretID string
	if e = stStore.DB.QueryRow(`SELECT id FROM secrets WHERE ns='demo' AND label='smoke-fake'`).Scan(&secretID); e != nil {
		t.Fatal(e)
	}
	t.Setenv("SWSV_URL", srv.URL)
	t.Setenv("SWSV_TOKEN", token)
	t.Setenv("SWSV_NS", "demo")
	body := map[string]any{"secret": "vault:demo/" + secretID, "method": "GET", "url": backend.URL, "headers": map[string]string{"Authorization": "Bearer caller", "Cookie": "fake=session"}}
	b, _ := json.Marshal(body)
	req, _ = http.NewRequest("POST", srv.URL+"/v1/fetch", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, e = httpClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	fetchBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("fetch failed: %d %s", resp.StatusCode, fetchBody)
	}
	var fetched map[string]any
	if json.Unmarshal(fetchBody, &fetched) != nil {
		t.Fatal("invalid fetch response")
	}
	rendered, _ := json.Marshal(fetched)
	if strings.Contains(string(rendered), sentinel) || strings.Contains(string(rendered), base64.StdEncoding.EncodeToString([]byte(sentinel))) || strings.Contains(string(rendered), url.QueryEscape(sentinel)) || strings.Contains(string(rendered), url.PathEscape(sentinel)) {
		t.Fatal("fetch response leaked injected value")
	}
	select {
	case got := <-received:
		if got != sentinel {
			t.Fatal("backend did not receive injected header")
		}
	case <-time.After(time.Second):
		t.Fatal("backend did not receive fetch request")
	}
	req, _ = http.NewRequest("POST", srv.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"vault_list","arguments":{"ns":"demo"}}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, e = httpClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	mcpBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(mcpBody), "smoke-fake") {
		t.Fatalf("MCP list call failed: %d %s", resp.StatusCode, mcpBody)
	}
	if strings.Contains(string(mcpBody), sentinel) || strings.Contains(string(mcpBody), base64.StdEncoding.EncodeToString([]byte(sentinel))) || strings.Contains(string(mcpBody), url.QueryEscape(sentinel)) {
		t.Fatal("MCP list leaked value")
	}
	var audit string
	if e = stStore.DB.QueryRow(`SELECT group_concat(action||result,' ') FROM audit`).Scan(&audit); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(audit, sentinel) || strings.Contains(initErr+tokenOut+tokenErr+out, sentinel) {
		t.Fatal("audit leaked value")
	}
}

func TestKeygenRefusesOverwrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "existing.key")
	original := []byte("FAKE-KEY-FILE-CONTENT")
	if err := os.WriteFile(p, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := keygen([]string{"--out", p}); err == nil {
		t.Fatal("keygen overwrote an existing file")
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatal("existing key file changed")
	}
}
