package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// quickProjectSession 注册一个管理面板会话，便于直接 POST 快速流程。
func quickProjectSession(cookie, csrf string) {
	sessions.Lock()
	sessions.m[cookie] = adminSession{csrf: csrf, created: time.Now(), last: time.Now()}
	sessions.Unlock()
}

// storedBindings 读回某个密钥落库后的绑定，用来断言 allow_resolve 的实际取值。
func storedBindings(t *testing.T, s *Server, id string) Binding {
	t.Helper()
	var raw string
	if err := s.S.DB.QueryRow(`SELECT bindings FROM secrets WHERE id=?`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var bd Binding
	if err := json.Unmarshal([]byte(raw), &bd); err != nil {
		t.Fatal(err)
	}
	return bd
}

// clientRequestFrom 用指定的来源地址调用客户端接口，验证 CIDR 门禁。
func clientRequestFrom(t *testing.T, s *Server, token, remoteAddr, method, path, body string) (int, string) {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = remoteAddr
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

// 测试 1：默认接入只给代发（fetch）。
func TestQuickProjectDefaultsToFetchOnly(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	const sentinel = "SWSV-FETCH-ONLY-BACKEND-SENTINEL"
	seen := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
		_, _ = w.Write([]byte("fetch-only-ok"))
	}))
	defer backend.Close()
	secret, err := s.save(SecretRequest{NS: unassignedNS, Label: "fetch-only-fake", Provider: "github-pat", Type: "token", Value: sentinel,
		Bindings: Binding{Hosts: []string{strings.TrimPrefix(backend.URL, "http://")}, AllowPrivate: true, AllowHTTP: true, AllowResolve: true}}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf := "fetch-only-session", "fetch-only-csrf"
	quickProjectSession(cookie, csrf)
	w := adminPageRequest(s, cookie, http.MethodPost, "/admin/quick/project", url.Values{
		"csrf": {csrf}, "project": {"fetch-only-project"}, "client": {"fetch-only-client"}, "secret": {secret.ID}})
	if w.Code != http.StatusOK {
		t.Fatalf("quick project status=%d body=%s", w.Code, w.Body.String())
	}
	tokens := tokenPattern.FindAllString(w.Body.String(), -1)
	if len(tokens) == 0 {
		t.Fatal("one-time client token missing from result page")
	}
	var scopes string
	if err := st.DB.QueryRow(`SELECT scopes FROM clients WHERE name='fetch-only-client'`).Scan(&scopes); err != nil {
		t.Fatal(err)
	}
	if scopes != "secrets:list,fetch" || hasScope(scopes, "resolve") {
		t.Fatalf("default quick-flow scopes=%q, want secrets:list,fetch without resolve", scopes)
	}
	resolveBody, _ := json.Marshal(map[string]string{"secret": "vault:fetch-only-project/" + secret.ID})
	code, out := requestWithToken(t, s, tokens[0], http.MethodPost, "/v1/resolve", string(resolveBody))
	if code != http.StatusForbidden || strings.Contains(out, sentinel) {
		t.Fatalf("fetch-only client resolved plaintext: status=%d body=%s", code, out)
	}
	fetchBody, _ := json.Marshal(map[string]any{"secret": "vault:fetch-only-project/" + secret.ID, "method": "GET", "url": backend.URL + "/"})
	code, out = requestWithToken(t, s, tokens[0], http.MethodPost, "/v1/fetch", string(fetchBody))
	if code != http.StatusOK || !strings.Contains(out, "fetch-only-ok") {
		t.Fatalf("fetch-only client could not use /v1/fetch: status=%d body=%s", code, out)
	}
	select {
	case got := <-seen:
		if got != "Bearer "+sentinel {
			t.Fatalf("outbound fetch injected %q, want the bound credential", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("test backend never received the delegated fetch")
	}
}

// 测试 2：勾选「允许取出明文」后才授予 resolve。
func TestQuickProjectAllowResolveGrantsPlaintext(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	const sentinel = "SWSV-ALLOW-RESOLVE-SENTINEL"
	secret, err := s.save(SecretRequest{NS: unassignedNS, Label: "allow-resolve-fake", Provider: "github-pat", Type: "token", Value: sentinel,
		Bindings: Binding{AllowResolve: true}}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf := "allow-resolve-session", "allow-resolve-csrf"
	quickProjectSession(cookie, csrf)
	w := adminPageRequest(s, cookie, http.MethodPost, "/admin/quick/project", url.Values{
		"csrf": {csrf}, "project": {"allow-resolve-project"}, "client": {"allow-resolve-client"}, "secret": {secret.ID}, "allow_resolve": {"on"}})
	if w.Code != http.StatusOK {
		t.Fatalf("quick project status=%d body=%s", w.Code, w.Body.String())
	}
	tokens := tokenPattern.FindAllString(w.Body.String(), -1)
	if len(tokens) == 0 {
		t.Fatal("one-time client token missing from result page")
	}
	var scopes string
	if err := st.DB.QueryRow(`SELECT scopes FROM clients WHERE name='allow-resolve-client'`).Scan(&scopes); err != nil {
		t.Fatal(err)
	}
	if !hasScope(scopes, "resolve") {
		t.Fatalf("opted-in client scopes=%q, want resolve", scopes)
	}
	if bd := storedBindings(t, s, secret.ID); !bd.AllowResolve {
		t.Fatal("opted-in secret binding did not set allow_resolve")
	}
	body, _ := json.Marshal(map[string]string{"secret": "vault:allow-resolve-project/" + secret.ID})
	code, out := requestWithToken(t, s, tokens[0], http.MethodPost, "/v1/resolve", string(body))
	if code != http.StatusOK || !strings.Contains(out, sentinel) {
		t.Fatalf("opted-in client could not resolve plaintext: status=%d body=%s", code, out)
	}
}

// 测试 3：不勾选时，本项目已有的 allow_resolve 保持不变，从未关联移入的置为 false。
func TestQuickProjectKeepsExistingAllowResolveAndClearsMovedSecrets(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	existing, err := s.save(SecretRequest{NS: "keep-project", Label: "keep-existing-fake", Provider: "github-pat", Type: "token", Value: "SWSV-KEEP-EXISTING",
		Bindings: Binding{AllowResolve: true}}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	moved, err := s.save(SecretRequest{NS: unassignedNS, Label: "keep-moved-fake", Provider: "github-pat", Type: "token", Value: "SWSV-KEEP-MOVED",
		Bindings: Binding{AllowResolve: true}}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf := "keep-resolve-session", "keep-resolve-csrf"
	quickProjectSession(cookie, csrf)
	w := adminPageRequest(s, cookie, http.MethodPost, "/admin/quick/project", url.Values{
		"csrf": {csrf}, "project": {"keep-project"}, "client": {"keep-client"}, "secret": {existing.ID, moved.ID}})
	if w.Code != http.StatusOK {
		t.Fatalf("quick project status=%d body=%s", w.Code, w.Body.String())
	}
	if bd := storedBindings(t, s, existing.ID); !bd.AllowResolve {
		t.Fatal("an existing project secret lost its allow_resolve flag")
	}
	if bd := storedBindings(t, s, moved.ID); bd.AllowResolve {
		t.Fatal("a secret moved out of the unassigned pool kept allow_resolve")
	}
	var scopes string
	if err := st.DB.QueryRow(`SELECT scopes FROM clients WHERE name='keep-client'`).Scan(&scopes); err != nil {
		t.Fatal(err)
	}
	if hasScope(scopes, "resolve") {
		t.Fatalf("scopes=%q must not include resolve when the box is unchecked", scopes)
	}
	var movedNS string
	if err := st.DB.QueryRow(`SELECT ns FROM secrets WHERE id=?`, moved.ID).Scan(&movedNS); err != nil || movedNS != "keep-project" {
		t.Fatalf("moved secret ns=%q err=%v", movedNS, err)
	}
}

// 测试 4：限制来源 IP，单个 IPv4 归一为 /32 并真正生效。
func TestQuickProjectRestrictsSourceCIDR(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	cookie, csrf := "cidr-session", "cidr-csrf"
	quickProjectSession(cookie, csrf)
	w := adminPageRequest(s, cookie, http.MethodPost, "/admin/quick/project", url.Values{
		"csrf": {csrf}, "project": {"cidr-project"}, "client": {"cidr-client"}, "cidrs": {"10.9.9.9"}})
	if w.Code != http.StatusOK {
		t.Fatalf("quick project status=%d body=%s", w.Code, w.Body.String())
	}
	var stored string
	if err := st.DB.QueryRow(`SELECT cidrs FROM clients WHERE name='cidr-client'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "10.9.9.9/32" {
		t.Fatalf("stored cidrs=%q, want 10.9.9.9/32", stored)
	}
	if !strings.Contains(w.Body.String(), "10.9.9.9/32") {
		t.Fatal("result page did not show the effective source CIDR")
	}
	tokens := tokenPattern.FindAllString(w.Body.String(), -1)
	if len(tokens) == 0 {
		t.Fatal("one-time client token missing from result page")
	}
	code, out := clientRequestFrom(t, s, tokens[0], "10.9.9.10:41234", http.MethodGet, "/v1/secrets?ns=cidr-project", "")
	if code != http.StatusForbidden {
		t.Fatalf("request from outside the CIDR status=%d body=%s", code, out)
	}
	code, out = clientRequestFrom(t, s, tokens[0], "10.9.9.9:41234", http.MethodGet, "/v1/secrets?ns=cidr-project", "")
	if code != http.StatusOK {
		t.Fatalf("request from inside the CIDR status=%d body=%s", code, out)
	}
}

// 测试 5：非法 CIDR 返回 400，且不留下任何半成品。
func TestQuickProjectRejectsInvalidSourceCIDRWithoutPartialCreate(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	secret, err := s.save(SecretRequest{NS: unassignedNS, Label: "bad-cidr-fake", Provider: "github-pat", Type: "token", Value: "SWSV-BAD-CIDR",
		Bindings: Binding{AllowResolve: true}}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf := "bad-cidr-session", "bad-cidr-csrf"
	quickProjectSession(cookie, csrf)
	for _, bad := range []string{"not-an-ip", "10.9.9.9/33", "10.0.0.0/8, 2001:db8::/129"} {
		w := adminPageRequest(s, cookie, http.MethodPost, "/admin/quick/project", url.Values{
			"csrf": {csrf}, "project": {"bad-cidr-project"}, "client": {"bad-cidr-client"}, "cidrs": {bad}, "secret": {secret.ID}})
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "限制来源 IP 无效") {
			t.Fatalf("cidr %q: status=%d body=%s", bad, w.Code, w.Body.String())
		}
	}
	var projects, clients int
	if err := st.DB.QueryRow(`SELECT count(*) FROM namespaces WHERE name='bad-cidr-project'`).Scan(&projects); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow(`SELECT count(*) FROM clients WHERE ns='bad-cidr-project'`).Scan(&clients); err != nil {
		t.Fatal(err)
	}
	if projects != 0 || clients != 0 {
		t.Fatalf("invalid CIDR left a partial project/client: projects=%d clients=%d", projects, clients)
	}
	var ns string
	if err := st.DB.QueryRow(`SELECT ns FROM secrets WHERE id=?`, secret.ID).Scan(&ns); err != nil || ns != unassignedNS {
		t.Fatalf("selected secret was moved despite the rejected request: ns=%q err=%v", ns, err)
	}
}

// 测试 6：结果页按权限展示，且任何模式下都不出现密钥明文。
func TestQuickProjectResultPageReflectsResolvePermission(t *testing.T) {
	s, _, _, _ := testServer(t, "secrets:list")
	previous := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	const defaultSentinel = "SWSV-RESULT-DEFAULT-SENTINEL"
	const resolveSentinel = "SWSV-RESULT-RESOLVE-SENTINEL"
	defaultSecret, err := s.save(SecretRequest{NS: unassignedNS, Label: "result-default-fake", Provider: "github-pat", Type: "token", Value: defaultSentinel,
		Bindings: Binding{AllowResolve: true}}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	resolveSecret, err := s.save(SecretRequest{NS: unassignedNS, Label: "result-resolve-fake", Provider: "github-pat", Type: "token", Value: resolveSentinel,
		Bindings: Binding{AllowResolve: true}}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf := "result-page-session", "result-page-csrf"
	quickProjectSession(cookie, csrf)

	fetchOnly := adminPageRequest(s, cookie, http.MethodPost, "/admin/quick/project", url.Values{
		"csrf": {csrf}, "project": {"result-default-project"}, "client": {"result-default-client"}, "secret": {defaultSecret.ID}})
	if fetchOnly.Code != http.StatusOK {
		t.Fatalf("quick project status=%d body=%s", fetchOnly.Code, fetchOnly.Body.String())
	}
	fetchOnlyBody := fetchOnly.Body.String()
	if !strings.Contains(fetchOnlyBody, "/v1/fetch") || !strings.Contains(fetchOnlyBody, "MCP 配置示例") {
		t.Fatal("fetch-only result page is missing the delegation or MCP example")
	}
	for _, forbidden := range []string{"swsvault run", "git-credential"} {
		if strings.Contains(fetchOnlyBody, forbidden) {
			t.Fatalf("fetch-only result page still shows %q", forbidden)
		}
	}
	if !strings.Contains(fetchOnlyBody, "此令牌只能代发请求，不能取出明文") {
		t.Fatal("fetch-only result page is missing the plaintext warning")
	}
	if strings.Contains(fetchOnlyBody, defaultSentinel) {
		t.Fatal("fetch-only result page leaked the secret value")
	}

	resolvePage := adminPageRequest(s, cookie, http.MethodPost, "/admin/quick/project", url.Values{
		"csrf": {csrf}, "project": {"result-resolve-project"}, "client": {"result-resolve-client"}, "secret": {resolveSecret.ID}, "allow_resolve": {"on"}})
	if resolvePage.Code != http.StatusOK {
		t.Fatalf("quick project status=%d body=%s", resolvePage.Code, resolvePage.Body.String())
	}
	resolvePageBody := resolvePage.Body.String()
	if !strings.Contains(resolvePageBody, "swsvault run") || !strings.Contains(resolvePageBody, "git-credential") {
		t.Fatal("resolve result page is missing the run/git-credential examples")
	}
	if strings.Contains(resolvePageBody, "/v1/fetch") {
		t.Fatal("resolve result page should not show the delegation example")
	}
	if !strings.Contains(resolvePageBody, "此令牌可以取出明文，不要交给 AI") {
		t.Fatal("resolve result page is missing the plaintext reminder")
	}
	if strings.Contains(resolvePageBody, resolveSentinel) {
		t.Fatal("resolve result page leaked the secret value")
	}
	if strings.Contains(logs.String(), defaultSentinel) || strings.Contains(logs.String(), resolveSentinel) {
		t.Fatalf("quick-flow logs leaked a secret value: %s", logs.String())
	}
}
