package api

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

var isoStampRE = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`)

// insertProjectClient 直接落一个属于某项目的接入方，用来构造「历史数据」前置状态。
func insertProjectClient(t *testing.T, s *Server, ns, name, scopes string) string {
	t.Helper()
	if _, err := s.S.DB.Exec(`INSERT INTO namespaces(id,name,created_at) VALUES(?,?,?) ON CONFLICT(name) DO NOTHING`, ns, ns, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	token := "swsv_rework-" + ns + "-" + name
	sum := sha256.Sum256([]byte(token))
	id := "client-" + ns + "-" + name
	if _, err := s.S.DB.Exec(`INSERT INTO clients(id,ns,name,token_hash,scopes,cidrs,expires_at,disabled,created_at) VALUES(?,?,?,?,?,'','',0,?)`,
		id, ns, name, sum[:], scopes, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	return token
}

func fetchWith(t *testing.T, s *Server, token, ns, secretID, target string) (int, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"secret": "vault:" + ns + "/" + secretID, "method": "GET", "url": target + "/"})
	return requestWithToken(t, s, token, http.MethodPost, "/v1/fetch", string(body))
}

// 测试 1（复现 H1）：未勾选的空授权列表密钥，对新接入方必须 403。
func TestReworkUnselectedOpenSecretIsDeniedForNewClient(t *testing.T) {
	s, _, _, _ := testServer(t, "secrets:list")
	backend := projectBackend(t)
	host := backendHost(backend)
	open := Binding{Hosts: []string{host}, AllowPrivate: true, AllowHTTP: true}
	x := seedProjectSecret(t, s, "proj-z", "x-fake", "SWSV-RW-X", open)
	y := seedProjectSecret(t, s, "proj-z", "y-fake", "SWSV-RW-Y", open)
	if bd := storedBindings(t, s, y.ID); len(bd.AllowedClients) != 0 || bd.NoClientAccess {
		t.Fatalf("precondition: Y should start wide open, got %+v", bd)
	}
	cookie, csrf := "rw-h1-session", "rw-h1-csrf"
	quickProjectSession(cookie, csrf)
	w := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/proj-z/clients/new", url.Values{
		"csrf": {csrf}, "name": {"a"}, "secret": {x.ID}})
	if w.Code != http.StatusOK {
		t.Fatalf("add client status=%d body=%s", w.Code, w.Body.String())
	}
	token := firstToken(t, w.Body.String())
	if code, out := fetchWith(t, s, token, "proj-z", x.ID, backend.URL); code != http.StatusOK {
		t.Fatalf("selected secret must stay usable: %d %s", code, out)
	}
	if code, out := fetchWith(t, s, token, "proj-z", y.ID, backend.URL); code != http.StatusForbidden {
		t.Fatalf("H1: unselected open secret is still reachable by the new client: %d %s", code, out)
	}
	if bd := storedBindings(t, s, y.ID); !bd.NoClientAccess || len(bd.AllowedClients) != 0 {
		t.Fatalf("H1: unselected secret should be explicitized to nobody, got %+v", bd)
	}
}

// 测试 2（复现 H2）：勾选空授权列表密钥时，已有接入方不能被静默撤权。
func TestReworkExistingClientKeepsAccessWhenSecretIsSelected(t *testing.T) {
	s, _, _, _ := testServer(t, "secrets:list")
	backend := projectBackend(t)
	host := backendHost(backend)
	y := seedProjectSecret(t, s, "proj-h2", "y-fake", "SWSV-RW-H2", Binding{Hosts: []string{host}, AllowPrivate: true, AllowHTTP: true})
	tokenA := insertProjectClient(t, s, "proj-h2", "a", "secrets:list,fetch")
	if code, out := fetchWith(t, s, tokenA, "proj-h2", y.ID, backend.URL); code != http.StatusOK {
		t.Fatalf("precondition: client a should already use the wide-open secret: %d %s", code, out)
	}
	cookie, csrf := "rw-h2-session", "rw-h2-csrf"
	quickProjectSession(cookie, csrf)
	w := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/proj-h2/clients/new", url.Values{
		"csrf": {csrf}, "name": {"b"}, "secret": {y.ID}})
	if w.Code != http.StatusOK {
		t.Fatalf("add client status=%d body=%s", w.Code, w.Body.String())
	}
	tokenB := firstToken(t, w.Body.String())
	if code, out := fetchWith(t, s, tokenA, "proj-h2", y.ID, backend.URL); code != http.StatusOK {
		t.Fatalf("H2: existing client a was silently revoked: %d %s", code, out)
	}
	if code, out := fetchWith(t, s, tokenB, "proj-h2", y.ID, backend.URL); code != http.StatusOK {
		t.Fatalf("H2: new client b cannot use the secret it selected: %d %s", code, out)
	}
	if bd := storedBindings(t, s, y.ID); len(bd.AllowedClients) != 2 {
		t.Fatalf("H2: expected both clients authorized, got %+v", bd)
	}
}

// 测试 3：一步式「接入项目」走同一套规则。
func TestReworkQuickFlowAppliesSameAuthorizationRules(t *testing.T) {
	s, _, _, _ := testServer(t, "secrets:list")
	backend := projectBackend(t)
	host := backendHost(backend)
	open := Binding{Hosts: []string{host}, AllowPrivate: true, AllowHTTP: true}
	cookie, csrf := "rw-qf-session", "rw-qf-csrf"
	quickProjectSession(cookie, csrf)

	// 用例 A：未勾选的空列表密钥，对新客户端不开放。
	xa := seedProjectSecret(t, s, "proj-q1", "qa-x", "SWSV-RW-QX", open)
	ya := seedProjectSecret(t, s, "proj-q1", "qa-y", "SWSV-RW-QY", open)
	wa := adminPageRequest(s, cookie, http.MethodPost, "/admin/quick/project", url.Values{
		"csrf": {csrf}, "project": {"proj-q1"}, "client": {"qa"}, "secret": {xa.ID}})
	if wa.Code != http.StatusOK {
		t.Fatalf("quick project status=%d body=%s", wa.Code, wa.Body.String())
	}
	tokenA := firstToken(t, wa.Body.String())
	if code, out := fetchWith(t, s, tokenA, "proj-q1", xa.ID, backend.URL); code != http.StatusOK {
		t.Fatalf("quick flow: selected secret must stay usable: %d %s", code, out)
	}
	if code, out := fetchWith(t, s, tokenA, "proj-q1", ya.ID, backend.URL); code != http.StatusForbidden {
		t.Fatalf("quick flow H1: unselected open secret reachable: %d %s", code, out)
	}

	// 用例 B：勾选后，已有接入方权限不丢。
	yb := seedProjectSecret(t, s, "proj-q2", "qb-y", "SWSV-RW-Q2", open)
	tokenOld := insertProjectClient(t, s, "proj-q2", "old", "secrets:list,fetch")
	wb := adminPageRequest(s, cookie, http.MethodPost, "/admin/quick/project", url.Values{
		"csrf": {csrf}, "project": {"proj-q2"}, "client": {"qb"}, "secret": {yb.ID}})
	if wb.Code != http.StatusOK {
		t.Fatalf("quick project status=%d body=%s", wb.Code, wb.Body.String())
	}
	tokenNew := firstToken(t, wb.Body.String())
	if code, out := fetchWith(t, s, tokenOld, "proj-q2", yb.ID, backend.URL); code != http.StatusOK {
		t.Fatalf("quick flow H2: existing client lost access: %d %s", code, out)
	}
	if code, out := fetchWith(t, s, tokenNew, "proj-q2", yb.ID, backend.URL); code != http.StatusOK {
		t.Fatalf("quick flow H2: new client cannot use selected secret: %d %s", code, out)
	}
}

// 测试 4（M1）：使用范围页保存时必须保留 no_client_access。
func TestReworkBindingsPageKeepsNoClientAccess(t *testing.T) {
	s, _, _, _ := testServer(t, "secrets:list")
	backend := projectBackend(t)
	host := backendHost(backend)
	imported, err := s.save(SecretRequest{NS: unassignedNS, Label: "rw-import", Provider: "github-pat", Type: "token", Value: "SWSV-RW-IMPORT",
		Bindings: Binding{Hosts: []string{host}, AllowPrivate: true, AllowHTTP: true}}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	tokenA := insertProjectClient(t, s, "proj-m", "a", "secrets:list,fetch")
	cookie, csrf := "rw-m1-session", "rw-m1-csrf"
	quickProjectSession(cookie, csrf)
	imp := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/proj-m/secrets/import", url.Values{"csrf": {csrf}, "secret": {imported.ID}})
	if imp.Code != http.StatusSeeOther {
		t.Fatalf("import status=%d body=%s", imp.Code, imp.Body.String())
	}
	idA := clientIDByName(t, s, "proj-m", "a")
	// 留空保存：必须保持「尚未授权给任何接入方」。
	save := adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/"+imported.ID+"/bindings", url.Values{
		"csrf": {csrf}, "hosts": {host}, "allow_private": {"on"}, "allow_http": {"on"}})
	if save.Code != http.StatusSeeOther {
		t.Fatalf("bindings save status=%d body=%s", save.Code, save.Body.String())
	}
	if bd := storedBindings(t, s, imported.ID); !bd.NoClientAccess || len(bd.AllowedClients) != 0 {
		t.Fatalf("M1: empty save dropped no_client_access: %+v", bd)
	}
	if code, out := fetchWith(t, s, tokenA, "proj-m", imported.ID, backend.URL); code != http.StatusForbidden {
		t.Fatalf("M1: unauthorized secret reachable after empty save: %d %s", code, out)
	}
	page := adminPageRequest(s, cookie, http.MethodGet, "/admin/secrets/"+imported.ID+"/bindings", nil).Body.String()
	if !strings.Contains(page, "当前尚未授权给任何接入方") {
		t.Fatal("M1: bindings page must explain the unauthorized state")
	}
	// 填入接入方 ID：改为显式授权。
	grant := adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/"+imported.ID+"/bindings", url.Values{
		"csrf": {csrf}, "hosts": {host}, "allowed_clients": {idA}, "allow_private": {"on"}, "allow_http": {"on"}})
	if grant.Code != http.StatusSeeOther {
		t.Fatalf("bindings grant status=%d body=%s", grant.Code, grant.Body.String())
	}
	if bd := storedBindings(t, s, imported.ID); bd.NoClientAccess {
		t.Fatalf("M1: filling allowed_clients must clear no_client_access: %+v", bd)
	}
	if code, out := fetchWith(t, s, tokenA, "proj-m", imported.ID, backend.URL); code != http.StatusOK {
		t.Fatalf("M1: authorized client still denied: %d %s", code, out)
	}
}

// 测试 5（C）：从项目详情页新建的密钥默认未授权给任何接入方；旧入口行为不变。
func TestReworkProjectDetailNewSecretStartsUnauthorized(t *testing.T) {
	s, _, _, _ := testServer(t, "secrets:list")
	tokenA := insertProjectClient(t, s, "proj-c", "a", "secrets:list,fetch")
	cookie, csrf := "rw-c-session", "rw-c-csrf"
	quickProjectSession(cookie, csrf)
	form := url.Values{"csrf": {csrf}, "provider": {"github-pat"}, "label": {"rw-new"}, "value": {"SWSV-RW-NEW"}, "project": {"proj-c"}}
	marked := cloneValues(form)
	marked.Set("from", "project")
	w := adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/new", marked)
	if w.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "尚未授权给任何接入方") {
		t.Fatal("C: created page must prompt for authorization")
	}
	var id string
	if err := s.S.DB.QueryRow(`SELECT id FROM secrets WHERE ns='proj-c' AND label='rw-new'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if bd := storedBindings(t, s, id); !bd.NoClientAccess {
		t.Fatalf("C: project-detail secret should start unauthorized, got %+v", bd)
	}
	if code, out := fetchWith(t, s, tokenA, "proj-c", id, "https://api.github.com"); code != http.StatusForbidden {
		t.Fatalf("C: existing client used an unauthorized new secret: %d %s", code, out)
	}
	// 旧入口（不带 from）保持原行为。
	legacy := cloneValues(form)
	legacy.Set("label", "rw-legacy")
	if lw := adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/new", legacy); lw.Code != http.StatusOK {
		t.Fatalf("legacy create status=%d", lw.Code)
	}
	var legacyID string
	if err := s.S.DB.QueryRow(`SELECT id FROM secrets WHERE ns='proj-c' AND label='rw-legacy'`).Scan(&legacyID); err != nil {
		t.Fatal(err)
	}
	if bd := storedBindings(t, s, legacyID); bd.NoClientAccess {
		t.Fatalf("legacy entry must keep project-wide behaviour, got %+v", bd)
	}
}

// 测试 6：L1（简介只出现一次）、L2（时间格式）、L3（结果页来源 IP / 空使用范围）。
func TestReworkPageLows(t *testing.T) {
	s, _, _, _ := testServer(t, "secrets:list")
	backend := projectBackend(t)
	host := backendHost(backend)
	secret := seedProjectSecret(t, s, "proj-l", "l-fake", "SWSV-RW-L", Binding{Hosts: []string{host}, AllowPrivate: true, AllowHTTP: true})
	insertProjectClient(t, s, "proj-l", "l-a", "secrets:list,fetch")
	cookie, csrf := "rw-l-session", "rw-l-csrf"
	quickProjectSession(cookie, csrf)
	detail := adminPageRequest(s, cookie, http.MethodGet, "/admin/projects/proj-l", nil).Body.String()
	if strings.Contains(detail, "<h2>简介</h2>") {
		t.Fatal("L1: the 简介 block heading is duplicated")
	}
	if isoStampRE.MatchString(detail) {
		t.Fatalf("L2: detail page still prints a raw ISO timestamp")
	}
	// C：项目里的新建密钥入口要带 from=project；该入口由本卡 E 移到「放入密钥」小页面。
	addPage := adminPageRequest(s, cookie, http.MethodGet, "/admin/projects/proj-l/secrets/add", nil).Body.String()
	if !strings.Contains(addPage, "from=project") {
		t.Fatal("C: the project detail entry must be marked so new secrets start unauthorized")
	}
	res := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/proj-l/clients/new", url.Values{
		"csrf": {csrf}, "name": {"l-client"}, "secret": {secret.ID}})
	body := res.Body.String()
	if !strings.Contains(body, "来源 IP：不限") {
		t.Fatal("L3: result page must show 来源 IP：不限 when no CIDR was given")
	}
	if strings.Contains(body, "使用范围：</p>") {
		t.Fatal("L3: result page still renders an empty 使用范围 line")
	}
	locked := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/proj-l/clients/new", url.Values{
		"csrf": {csrf}, "name": {"l-locked"}, "secret": {secret.ID}, "cidrs": {"10.9.9.9"}})
	if !strings.Contains(locked.Body.String(), "来源 IP：10.9.9.9/32") {
		t.Fatal("L3: result page must show the effective CIDR")
	}
}
