package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var visibleTagRE = regexp.MustCompile(`<[^>]*>`)

func visibleText(body string) string {
	return visibleTagRE.ReplaceAllString(body, " ")
}

// projectBackend 起一个本地测试后端，返回它和它绑定时用的主机串。
func projectBackend(t *testing.T) *httptest.Server {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("project-fetch-ok"))
	}))
	t.Cleanup(backend.Close)
	return backend
}

func backendHost(backend *httptest.Server) string { return strings.TrimPrefix(backend.URL, "http://") }

// seedProjectSecret 直接落一个属于某项目的密钥（绕过面板，便于构造前置状态）。
func seedProjectSecret(t *testing.T, s *Server, ns, label, value string, bd Binding) Metadata {
	t.Helper()
	m, err := s.save(SecretRequest{NS: ns, Label: label, Provider: "github-pat", Type: "token", Value: value, Bindings: bd}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func clientIDByName(t *testing.T, s *Server, ns, name string) string {
	t.Helper()
	var id string
	if err := s.S.DB.QueryRow(`SELECT id FROM clients WHERE ns=? AND name=?`, ns, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func firstToken(t *testing.T, body string) string {
	t.Helper()
	tokens := tokenPattern.FindAllString(body, -1)
	if len(tokens) == 0 {
		t.Fatal("one-time client token missing from result page")
	}
	return tokens[0]
}

// 测试 2：新建项目；列表与详情能看到简介；保留名 / 重名 / 简介超长都是 400 且不落库。
func TestProjectCreateShowsDescriptionAndRejectsBadInput(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	cookie, csrf := "proj-create-session", "proj-create-csrf"
	quickProjectSession(cookie, csrf)
	const description = "Cloudflare DNS 令牌，给多个站点复用"
	w := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/new", url.Values{"csrf": {csrf}, "name": {"cf-dns"}, "description": {description}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/projects/cf-dns" {
		t.Fatalf("create project status=%d location=%q body=%s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	list := adminPageRequest(s, cookie, http.MethodGet, "/admin/projects", nil)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "cf-dns") || !strings.Contains(list.Body.String(), description) {
		t.Fatalf("project list missing name/description: %d %s", list.Code, list.Body.String())
	}
	if strings.Contains(list.Body.String(), "_unassigned") || strings.Contains(list.Body.String(), "未关联密钥") {
		t.Fatal("project list must not expose the reserved unassigned bucket")
	}
	detail := adminPageRequest(s, cookie, http.MethodGet, "/admin/projects/cf-dns", nil)
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), description) {
		t.Fatalf("project detail missing description: %d", detail.Code)
	}
	reserved := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/new", url.Values{"csrf": {csrf}, "name": {"_internal"}, "description": {""}})
	if reserved.Code != http.StatusBadRequest || !strings.Contains(reserved.Body.String(), "这是系统保留名称") {
		t.Fatalf("reserved name status=%d body=%s", reserved.Code, reserved.Body.String())
	}
	duplicate := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/new", url.Values{"csrf": {csrf}, "name": {"cf-dns"}, "description": {""}})
	if duplicate.Code != http.StatusBadRequest {
		t.Fatalf("duplicate name status=%d", duplicate.Code)
	}
	tooLong := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/new", url.Values{"csrf": {csrf}, "name": {"long-desc"}, "description": {strings.Repeat("简", 201)}})
	if tooLong.Code != http.StatusBadRequest {
		t.Fatalf("over-long description status=%d", tooLong.Code)
	}
	var created int
	if err := st.DB.QueryRow(`SELECT count(*) FROM namespaces WHERE name IN ('_internal','long-desc')`).Scan(&created); err != nil {
		t.Fatal(err)
	}
	if created != 0 {
		t.Fatalf("rejected requests created %d projects", created)
	}
	var total int
	if err := st.DB.QueryRow(`SELECT count(*) FROM namespaces WHERE name='cf-dns'`).Scan(&total); err != nil || total != 1 {
		t.Fatalf("cf-dns rows=%d err=%v", total, err)
	}
}

// 测试 3：默认添加接入方只给代发，只有勾选的密钥被授权。
func TestProjectClientDefaultsToFetchOnly(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	backend := projectBackend(t)
	selected := seedProjectSecret(t, s, "proj-a", "selected-fake", "SWSV-PROJ-SELECTED", Binding{Hosts: []string{backendHost(backend)}, AllowPrivate: true, AllowHTTP: true})
	other := seedProjectSecret(t, s, "proj-a", "unselected-fake", "SWSV-PROJ-UNSELECTED", Binding{Hosts: []string{backendHost(backend)}, AllowPrivate: true, AllowHTTP: true, AllowedClients: []string{"someone-else"}})
	cookie, csrf := "proj-client-session", "proj-client-csrf"
	quickProjectSession(cookie, csrf)
	w := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/proj-a/clients/new", url.Values{
		"csrf": {csrf}, "name": {"ci"}, "note": {"CI 流水线"}, "secret": {selected.ID}})
	if w.Code != http.StatusOK {
		t.Fatalf("add client status=%d body=%s", w.Code, w.Body.String())
	}
	token := firstToken(t, w.Body.String())
	var scopes string
	if err := st.DB.QueryRow(`SELECT scopes FROM clients WHERE ns='proj-a' AND name='ci'`).Scan(&scopes); err != nil {
		t.Fatal(err)
	}
	if scopes != "secrets:list,fetch" || hasScope(scopes, "resolve") {
		t.Fatalf("default scopes=%q, want secrets:list,fetch", scopes)
	}
	clientID := clientIDByName(t, s, "proj-a", "ci")
	body, _ := json.Marshal(map[string]string{"secret": "vault:proj-a/" + selected.ID})
	code, out := requestWithToken(t, s, token, http.MethodPost, "/v1/resolve", string(body))
	if code != http.StatusForbidden || strings.Contains(out, "SWSV-PROJ-SELECTED") {
		t.Fatalf("fetch-only client resolved plaintext: %d %s", code, out)
	}
	fetchBody, _ := json.Marshal(map[string]any{"secret": "vault:proj-a/" + selected.ID, "method": "GET", "url": backend.URL + "/"})
	code, out = requestWithToken(t, s, token, http.MethodPost, "/v1/fetch", string(fetchBody))
	if code != http.StatusOK || !strings.Contains(out, "project-fetch-ok") {
		t.Fatalf("selected secret fetch status=%d body=%s", code, out)
	}
	var selectedBindings Binding
	var raw string
	if err := st.DB.QueryRow(`SELECT bindings FROM secrets WHERE id=?`, selected.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(raw), &selectedBindings); err != nil {
		t.Fatal(err)
	}
	if len(selectedBindings.AllowedClients) != 1 || selectedBindings.AllowedClients[0] != clientID {
		t.Fatalf("selected secret allowed clients=%v, want [%s]", selectedBindings.AllowedClients, clientID)
	}
	var otherRaw string
	if err := st.DB.QueryRow(`SELECT bindings FROM secrets WHERE id=?`, other.ID).Scan(&otherRaw); err != nil {
		t.Fatal(err)
	}
	var otherBindings Binding
	if err := json.Unmarshal([]byte(otherRaw), &otherBindings); err != nil {
		t.Fatal(err)
	}
	for _, v := range otherBindings.AllowedClients {
		if v == clientID {
			t.Fatal("unselected secret was authorized for the new client")
		}
	}
	otherFetch, _ := json.Marshal(map[string]any{"secret": "vault:proj-a/" + other.ID, "method": "GET", "url": backend.URL + "/"})
	code, out = requestWithToken(t, s, token, http.MethodPost, "/v1/fetch", string(otherFetch))
	if code != http.StatusForbidden || strings.Contains(out, "SWSV-PROJ-UNSELECTED") {
		t.Fatalf("unselected secret fetch status=%d body=%s", code, out)
	}
}

// 测试 4：勾选取明文才给 resolve；不勾选不动已有的 allow_resolve，移入的密钥保持 false。
func TestProjectClientAllowResolveIsOptIn(t *testing.T) {
	s, _, _, _ := testServer(t, "secrets:list")
	existing := seedProjectSecret(t, s, "proj-b", "existing-fake", "SWSV-PROJ-EXISTING", Binding{AllowResolve: true})
	imported, err := s.save(SecretRequest{NS: unassignedNS, Label: "imported-fake", Provider: "github-pat", Type: "token", Value: "SWSV-PROJ-IMPORTED", Bindings: Binding{AllowResolve: true}}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf := "proj-resolve-session", "proj-resolve-csrf"
	quickProjectSession(cookie, csrf)
	imp := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/proj-b/secrets/import", url.Values{"csrf": {csrf}, "secret": {imported.ID}})
	if imp.Code != http.StatusSeeOther {
		t.Fatalf("import status=%d body=%s", imp.Code, imp.Body.String())
	}
	afterImport := storedBindings(t, s, imported.ID)
	if afterImport.AllowResolve || !afterImport.NoClientAccess || len(afterImport.AllowedClients) != 0 {
		t.Fatalf("imported secret bindings=%+v, want allow_resolve=false and no client access", afterImport)
	}
	// 不勾选取明文：已有的 true 保持 true，移入的保持 false。
	plain := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/proj-b/clients/new", url.Values{
		"csrf": {csrf}, "name": {"plain"}, "secret": {existing.ID, imported.ID}})
	if plain.Code != http.StatusOK {
		t.Fatalf("add plain client status=%d body=%s", plain.Code, plain.Body.String())
	}
	if bd := storedBindings(t, s, existing.ID); !bd.AllowResolve {
		t.Fatal("existing allow_resolve=true was cleared by an opt-out client")
	}
	if bd := storedBindings(t, s, imported.ID); bd.AllowResolve {
		t.Fatal("imported secret became resolvable without opting in")
	}
	// 勾选取明文：scopes 含 resolve，resolve 成功。
	opted := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/proj-b/clients/new", url.Values{
		"csrf": {csrf}, "name": {"opted"}, "secret": {existing.ID}, "allow_resolve": {"on"}})
	if opted.Code != http.StatusOK {
		t.Fatalf("add opted client status=%d body=%s", opted.Code, opted.Body.String())
	}
	token := firstToken(t, opted.Body.String())
	var scopes string
	if err := s.S.DB.QueryRow(`SELECT scopes FROM clients WHERE ns='proj-b' AND name='opted'`).Scan(&scopes); err != nil {
		t.Fatal(err)
	}
	if !hasScope(scopes, "resolve") {
		t.Fatalf("opted-in scopes=%q, want resolve", scopes)
	}
	body, _ := json.Marshal(map[string]string{"secret": "vault:proj-b/" + existing.ID})
	code, out := requestWithToken(t, s, token, http.MethodPost, "/v1/resolve", string(body))
	if code != http.StatusOK || !strings.Contains(out, "SWSV-PROJ-EXISTING") {
		t.Fatalf("opted-in resolve status=%d body=%s", code, out)
	}
}

// 测试 5：同一项目两个接入方共用一个密钥；停用其一不影响另一个。
func TestProjectClientsShareSecretAndDisableIsIsolated(t *testing.T) {
	s, _, _, _ := testServer(t, "secrets:list")
	backend := projectBackend(t)
	shared := seedProjectSecret(t, s, "proj-c", "shared-fake", "SWSV-PROJ-SHARED", Binding{Hosts: []string{backendHost(backend)}, AllowPrivate: true, AllowHTTP: true})
	cookie, csrf := "proj-share-session", "proj-share-csrf"
	quickProjectSession(cookie, csrf)
	first := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/proj-c/clients/new", url.Values{"csrf": {csrf}, "name": {"worker-a"}, "secret": {shared.ID}})
	second := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/proj-c/clients/new", url.Values{"csrf": {csrf}, "name": {"worker-b"}, "secret": {shared.ID}})
	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("add clients status=%d/%d", first.Code, second.Code)
	}
	tokenA, tokenB := firstToken(t, first.Body.String()), firstToken(t, second.Body.String())
	fetch := func(token string) (int, string) {
		body, _ := json.Marshal(map[string]any{"secret": "vault:proj-c/" + shared.ID, "method": "GET", "url": backend.URL + "/"})
		return requestWithToken(t, s, token, http.MethodPost, "/v1/fetch", string(body))
	}
	if code, out := fetch(tokenA); code != http.StatusOK {
		t.Fatalf("worker-a fetch status=%d body=%s", code, out)
	}
	if code, out := fetch(tokenB); code != http.StatusOK {
		t.Fatalf("worker-b fetch status=%d body=%s", code, out)
	}
	idA := clientIDByName(t, s, "proj-c", "worker-a")
	disable := adminPageRequest(s, cookie, http.MethodPost, "/admin/clients/"+idA+"/disable", url.Values{"csrf": {csrf}})
	if disable.Code != http.StatusSeeOther {
		t.Fatalf("disable status=%d", disable.Code)
	}
	if code, _ := fetch(tokenA); code != http.StatusUnauthorized {
		t.Fatalf("disabled worker-a fetch status=%d, want 401", code)
	}
	if code, out := fetch(tokenB); code != http.StatusOK {
		t.Fatalf("worker-b fetch after peer disable status=%d body=%s", code, out)
	}
}

// 测试 6：限制来源 IP —— 单 IP 归一为 /32，范围外 403、范围内成功，非法值 400 且无半成品。
func TestProjectClientSourceIPLock(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	seedProjectSecret(t, s, "proj-d", "cidr-fake", "SWSV-PROJ-CIDR", Binding{})
	cookie, csrf := "proj-cidr-session", "proj-cidr-csrf"
	quickProjectSession(cookie, csrf)
	w := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/proj-d/clients/new", url.Values{
		"csrf": {csrf}, "name": {"locked"}, "secret": {seedProjectSecret(t, s, "proj-d", "cidr-fake-2", "SWSV-PROJ-CIDR-2", Binding{}).ID}, "cidrs": {"10.9.9.9"}})
	if w.Code != http.StatusOK {
		t.Fatalf("add client status=%d body=%s", w.Code, w.Body.String())
	}
	var stored string
	if err := st.DB.QueryRow(`SELECT cidrs FROM clients WHERE ns='proj-d' AND name='locked'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "10.9.9.9/32" {
		t.Fatalf("stored cidrs=%q, want 10.9.9.9/32", stored)
	}
	if !strings.Contains(w.Body.String(), "10.9.9.9/32") {
		t.Fatal("result page did not show the effective source CIDR")
	}
	token := firstToken(t, w.Body.String())
	if code, out := clientRequestFrom(t, s, token, "10.9.9.10:41234", http.MethodGet, "/v1/secrets?ns=proj-d", ""); code != http.StatusForbidden {
		t.Fatalf("outside CIDR status=%d body=%s", code, out)
	}
	if code, out := clientRequestFrom(t, s, token, "10.9.9.9:41234", http.MethodGet, "/v1/secrets?ns=proj-d", ""); code != http.StatusOK {
		t.Fatalf("inside CIDR status=%d body=%s", code, out)
	}
	for _, bad := range []string{"not-an-ip", "10.9.9.9/33"} {
		bad1 := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/proj-d/clients/new", url.Values{
			"csrf": {csrf}, "name": {"bad-cidr"}, "secret": {seedProjectSecret(t, s, "proj-d", "cidr-fake-3", "SWSV-PROJ-CIDR-3", Binding{}).ID}, "cidrs": {bad}})
		if bad1.Code != http.StatusBadRequest || !strings.Contains(bad1.Body.String(), "限制来源 IP 无效") {
			t.Fatalf("cidr %q status=%d body=%s", bad, bad1.Code, bad1.Body.String())
		}
	}
	var count int
	if err := st.DB.QueryRow(`SELECT count(*) FROM clients WHERE ns='proj-d' AND name='bad-cidr'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("invalid CIDR created %d clients", count)
	}
}

// 测试 7：页面不泄露密钥明文；所有密钥页去掉旧链接条并把筛选收进 details；全站不出现「命名空间」。
func TestProjectPagesHidePlaintextAndDropLegacyChrome(t *testing.T) {
	s, _, _, _ := testServer(t, "secrets:list")
	const sentinel = "SWSV-PROJ-PAGE-SENTINEL"
	secret := seedProjectSecret(t, s, "proj-e", "page-fake", sentinel, Binding{})
	cookie, csrf := "proj-page-session", "proj-page-csrf"
	quickProjectSession(cookie, csrf)
	result := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/proj-e/clients/new", url.Values{
		"csrf": {csrf}, "name": {"page-client"}, "secret": {secret.ID}})
	if result.Code != http.StatusOK {
		t.Fatalf("add client status=%d", result.Code)
	}
	pages := map[string]string{
		"/admin/projects":           adminPageRequest(s, cookie, http.MethodGet, "/admin/projects", nil).Body.String(),
		"/admin/projects/proj-e":    adminPageRequest(s, cookie, http.MethodGet, "/admin/projects/proj-e", nil).Body.String(),
		"/admin/projects/e/clients": adminPageRequest(s, cookie, http.MethodGet, "/admin/projects/proj-e/clients/new", nil).Body.String(),
		"/admin/advanced/secrets":   adminPageRequest(s, cookie, http.MethodGet, "/admin/advanced/secrets", nil).Body.String(),
		"result":                    result.Body.String(),
	}
	for name, body := range pages {
		if strings.Contains(body, sentinel) {
			t.Fatalf("%s leaked the secret value", name)
		}
	}
	if strings.Contains(result.Body.String(), "export SWSV_TOKEN=") {
		t.Fatal("result page still prints a token assignment that would land in shell history")
	}
	allSecrets := pages["/admin/advanced/secrets"]
	if strings.Contains(allSecrets, `<a href="/admin/secrets/new">录入凭据</a>`) || strings.Contains(allSecrets, "SWSV Vault 管理面板") {
		t.Fatal("all-secrets page still shows the legacy underlined link bar")
	}
	if !strings.Contains(allSecrets, "<details") || !strings.Contains(allSecrets, "<summary>筛选</summary>") {
		t.Fatal("all-secrets page did not move its filters into a details block")
	}
	if strings.Index(allSecrets, `<input name="ns"`) < strings.Index(allSecrets, "<details") {
		t.Fatal("all-secrets filters are rendered outside the details block")
	}
	for _, path := range []string{"/admin/", "/admin/projects", "/admin/projects/new", "/admin/projects/proj-e", "/admin/projects/proj-e/clients/new", "/admin/advanced", "/admin/advanced/secrets", "/admin/clients", "/admin/audit", "/admin/secrets/new"} {
		body := visibleText(adminPageRequest(s, cookie, http.MethodGet, path, nil).Body.String())
		for _, bad := range []string{"命名空间", "namespace"} {
			if strings.Contains(body, bad) {
				t.Fatalf("%s still shows %q", path, bad)
			}
		}
	}
}

// 测试 8：四个写接口缺 CSRF 一律 403。
func TestProjectFormsRejectMissingCSRF(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	secret := seedProjectSecret(t, s, "proj-f", "csrf-fake", "SWSV-PROJ-CSRF", Binding{})
	imported, err := s.save(SecretRequest{NS: unassignedNS, Label: "csrf-imported", Provider: "github-pat", Type: "token", Value: "SWSV-PROJ-CSRF-IMPORT", Bindings: Binding{}}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := "proj-csrf-session", "proj-csrf-csrf"
	quickProjectSession(cookie, "proj-csrf-csrf")
	cases := []struct {
		path string
		form url.Values
	}{
		{"/admin/projects/new", url.Values{"name": {"csrf-project"}, "description": {""}}},
		{"/admin/projects/proj-f/description", url.Values{"description": {"x"}}},
		{"/admin/projects/proj-f/clients/new", url.Values{"name": {"csrf-client"}, "secret": {secret.ID}}},
		{"/admin/projects/proj-f/secrets/import", url.Values{"secret": {imported.ID}}},
	}
	for _, tc := range cases {
		w := adminPageRequest(s, cookie, http.MethodPost, tc.path, tc.form)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "csrf rejected") {
			t.Fatalf("%s without csrf status=%d body=%s", tc.path, w.Code, w.Body.String())
		}
	}
	var projects, clients int
	if err := st.DB.QueryRow(`SELECT count(*) FROM namespaces WHERE name='csrf-project'`).Scan(&projects); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow(`SELECT count(*) FROM clients WHERE ns='proj-f' AND name='csrf-client'`).Scan(&clients); err != nil {
		t.Fatal(err)
	}
	if projects != 0 || clients != 0 {
		t.Fatalf("csrf-rejected writes created rows: projects=%d clients=%d", projects, clients)
	}
	var ns string
	if err := st.DB.QueryRow(`SELECT ns FROM secrets WHERE id=?`, imported.ID).Scan(&ns); err != nil || ns != unassignedNS {
		t.Fatalf("csrf-rejected import moved the secret: ns=%q err=%v", ns, err)
	}
}
