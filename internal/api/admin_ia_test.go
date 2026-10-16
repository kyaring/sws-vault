package api

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

var panelCurrentTabRE = regexp.MustCompile(`<a class="tabitem" href="([^"]+)" aria-current="page">`)

func hasID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// TestAdminTabBarSettingsAndFormPages 覆盖卡里测试 1 的导航骨架部分（A1/A2）：
// 三个标签页都有标签栏且只有当前项带 aria-current="page"；表单页没有标签栏，
// 顶部是「取消」+ 标题；设置页给出三个入口。
func TestAdminTabBarSettingsAndFormPages(t *testing.T) {
	s, _, _, _ := testServer(t, "secrets:list")
	cookie, csrf := "ia-nav-session", "ia-nav-csrf"
	sessions.Lock()
	sessions.m[cookie] = adminSession{csrf: csrf, created: time.Now(), last: time.Now()}
	sessions.Unlock()

	for _, tc := range []struct{ path, href string }{
		{"/admin/secrets", "/admin/secrets"},
		{"/admin/projects", "/admin/projects"},
		{"/admin/audit", "/admin/audit"},
	} {
		w := adminPageRequest(s, cookie, http.MethodGet, tc.path, nil)
		body := w.Body.String()
		if w.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", tc.path, w.Code, body)
		}
		if !strings.Contains(body, `class="tabbar"`) {
			t.Errorf("%s 缺少底部标签栏", tc.path)
		}
		for _, label := range []string{"密钥", "项目", "记录"} {
			if !strings.Contains(body, label+"</a>") {
				t.Errorf("%s 标签栏缺少「%s」", tc.path, label)
			}
		}
		current := panelCurrentTabRE.FindAllStringSubmatch(body, -1)
		if len(current) != 1 {
			t.Fatalf("%s 应恰好有一个当前标签，实际 %d 个", tc.path, len(current))
		}
		if current[0][1] != tc.href {
			t.Errorf("%s 当前标签应为 %s，实际 %s", tc.path, tc.href, current[0][1])
		}
	}

	for _, tc := range []struct{ path, title string }{
		{"/admin/secrets/new", "新建密钥"},
		{"/admin/projects/new", "新建项目"},
	} {
		w := adminPageRequest(s, cookie, http.MethodGet, tc.path, nil)
		body := w.Body.String()
		if w.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", tc.path, w.Code, body)
		}
		if strings.Contains(body, `class="tabbar"`) {
			t.Errorf("%s 是表单页，不应显示标签栏", tc.path)
		}
		if !strings.Contains(body, `>取消</a>`) || !strings.Contains(body, ">"+tc.title+"</b>") {
			t.Errorf("%s 顶栏应显示「取消」和标题 %s", tc.path, tc.title)
		}
	}

	w := adminPageRequest(s, cookie, http.MethodGet, "/admin/settings", nil)
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("设置页 status=%d body=%s", w.Code, body)
	}
	for _, want := range []string{`href="/admin/password"`, `href="/admin/totp/enroll"`, `action="/admin/logout"`, "修改密码", "两步验证", "退出登录"} {
		if !strings.Contains(body, want) {
			t.Errorf("设置页缺少 %q", want)
		}
	}
	anon := adminPageRequest(s, "ia-no-such-session", http.MethodGet, "/admin/settings", nil)
	if anon.Code != http.StatusSeeOther || anon.Header().Get("Location") != "/admin/login" {
		t.Errorf("未登录访问设置页 status=%d location=%q", anon.Code, anon.Header().Get("Location"))
	}
}

// TestAdminGrantEndpoints 覆盖卡里测试 7（H 授权开关接口）：
// 跨项目 id 400 且库不变；未归入项目的密钥授权 400；缺 CSRF 403；
// 审计有 admin.grant.update 且不含值；关掉最后一个授权写「显式空」而不是「空 = 全部」。
func TestAdminGrantEndpoints(t *testing.T) {
	s, st, token, _ := testServer(t, "secrets:list,secrets:write,resolve,fetch")
	cookie, csrf := "ia-grant-session", "ia-grant-csrf"
	sessions.Lock()
	sessions.m[cookie] = adminSession{csrf: csrf, created: time.Now(), last: time.Now()}
	sessions.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := st.DB.Exec(`INSERT INTO namespaces(id,name,created_at) VALUES('ia-ns2','ia-ns2',?)`, now); err != nil {
		t.Fatal(err)
	}
	// ia-c2 属于另一个项目（跨项目用），ia-c3 与 c1 同项目（用来验证不得静默撤权）。
	for _, c := range []struct{ id, ns, name string }{
		{"ia-c2", "ia-ns2", "other"},
		{"ia-c3", "ns1", "second"},
	} {
		if _, err := st.DB.Exec(`INSERT INTO clients(id,ns,name,token_hash,scopes,created_at) VALUES(?,?,?,?, 'secrets:list,fetch', ?)`, c.id, c.ns, c.name, []byte(c.id), now); err != nil {
			t.Fatal(err)
		}
	}
	newSecret := func(ns, label string) string {
		m, err := s.save(SecretRequest{NS: ns, Label: label, Provider: "generic", Type: "token", Value: "SWSV-GRANT-SENTINEL", Bindings: Binding{Hosts: []string{"example.com"}, AllowResolve: true, NoClientAccess: true}}, false, "")
		if err != nil {
			t.Fatal(err)
		}
		return m.ID
	}
	k1 := newSecret("ns1", "ia-key-one")
	k2 := newSecret("ia-ns2", "ia-key-two")
	ku := newSecret(unassignedNS, "ia-key-unassigned")
	readBinding := func(id string) Binding {
		t.Helper()
		var raw string
		if err := st.DB.QueryRow(`SELECT bindings FROM secrets WHERE id=?`, id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var bd Binding
		if err := json.Unmarshal([]byte(raw), &bd); err != nil {
			t.Fatal(err)
		}
		return bd
	}

	// 1. 密钥维度：整体覆盖，写库成功。
	w := adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/"+k1+"/clients", url.Values{"csrf": {csrf}, "client": {"c1"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("密钥维度授权 status=%d body=%s", w.Code, w.Body.String())
	}
	bd := readBinding(k1)
	if len(bd.AllowedClients) != 1 || bd.AllowedClients[0] != "c1" || bd.NoClientAccess {
		t.Fatalf("密钥维度授权未写入：%+v", bd)
	}

	// 2. 跨项目接入方 → 400，且库不变。
	w = adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/"+k1+"/clients", url.Values{"csrf": {csrf}, "client": {"ia-c2"}})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("跨项目授权应 400，实际 %d", w.Code)
	}
	if bd = readBinding(k1); len(bd.AllowedClients) != 1 || bd.AllowedClients[0] != "c1" {
		t.Fatalf("跨项目授权改动了库：%+v", bd)
	}

	// 3. 未归入项目的密钥不可授权给任何人。
	w = adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/"+ku+"/clients", url.Values{"csrf": {csrf}, "client": {"c1"}})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("未归入项目的密钥授权应 400，实际 %d", w.Code)
	}
	if bd = readBinding(ku); len(bd.AllowedClients) != 0 || !bd.NoClientAccess {
		t.Fatalf("未归入项目的密钥被改动：%+v", bd)
	}

	// 4. 缺 CSRF → 403。
	w = adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/"+k1+"/clients", url.Values{"client": {"c1"}})
	if w.Code != http.StatusForbidden {
		t.Fatalf("缺 CSRF 应 403，实际 %d", w.Code)
	}

	// 5. 关掉最后一个授权 = 显式空：接入方仍然被拒绝，而不是「空列表 = 所有人可用」。
	w = adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/"+k1+"/clients", url.Values{"csrf": {csrf}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("清空授权 status=%d body=%s", w.Code, w.Body.String())
	}
	if bd = readBinding(k1); len(bd.AllowedClients) != 0 || !bd.NoClientAccess {
		t.Fatalf("关掉最后一个授权必须写成显式空：%+v", bd)
	}
	code, out := request(t, s, token, http.MethodPost, "/v1/fetch", `{"secret":"vault:ns1/`+k1+`","method":"GET","url":"https://example.com/"}`)
	if code != http.StatusForbidden {
		t.Fatalf("显式空之后接入方仍能代发：status=%d body=%s", code, out)
	}

	// 6. 接入方维度：把「空 = 全项目开放」显式化，再只增删这一个接入方。
	if _, err := st.DB.Exec(`UPDATE secrets SET bindings=? WHERE id=?`, `{"hosts":["example.com"],"allow_resolve":true}`, k1); err != nil {
		t.Fatal(err)
	}
	w = adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/ns1/clients/c1/secrets", url.Values{"csrf": {csrf}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("接入方维度清空 status=%d body=%s", w.Code, w.Body.String())
	}
	bd = readBinding(k1)
	if len(bd.AllowedClients) != 1 || bd.AllowedClients[0] != "ia-c3" || bd.NoClientAccess {
		t.Fatalf("显式化后不得静默撤掉其他接入方：%+v", bd)
	}

	// 7. 接入方维度：把 c1 授权进来，其他人不受影响。
	w = adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/ns1/clients/c1/secrets", url.Values{"csrf": {csrf}, "secret": {k1}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("接入方维度授权 status=%d body=%s", w.Code, w.Body.String())
	}
	bd = readBinding(k1)
	if len(bd.AllowedClients) != 2 || !hasID(bd.AllowedClients, "c1") || !hasID(bd.AllowedClients, "ia-c3") || bd.NoClientAccess {
		t.Fatalf("接入方维度授权不正确：%+v", bd)
	}

	// 8. 跨项目密钥 id → 400，且库不变。
	w = adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/ns1/clients/c1/secrets", url.Values{"csrf": {csrf}, "secret": {k2}})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("跨项目密钥授权应 400，实际 %d", w.Code)
	}
	if bd = readBinding(k2); len(bd.AllowedClients) != 0 || !bd.NoClientAccess {
		t.Fatalf("跨项目授权改动了库：%+v", bd)
	}

	// 9. 接入方不属于 URL 里的项目 → 404。
	w = adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/ia-ns2/clients/c1/secrets", url.Values{"csrf": {csrf}, "secret": {k2}})
	if w.Code != http.StatusNotFound {
		t.Fatalf("跨项目 URL 应 404，实际 %d", w.Code)
	}

	// 10. 审计：四次成功授权各一条 admin.grant.update，且不含密钥值。
	var grants int
	if err := st.DB.QueryRow(`SELECT count(*) FROM audit WHERE action='admin.grant.update'`).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if grants != 4 {
		t.Fatalf("admin.grant.update 审计条数应为 4，实际 %d", grants)
	}
	var dump string
	if err := st.DB.QueryRow(`SELECT COALESCE(group_concat(at||actor||ns||secret_id||action||target_host||result||source_ip,' '),'') FROM audit`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	if containsSentinel(dump, "SWSV-GRANT-SENTINEL") {
		t.Fatal("审计里出现了密钥值")
	}
}

var panelH2RE = regexp.MustCompile(`(?is)<h2>(.*?)</h2>`)

// TestSecretsTabGroupsAndKeyDetail 覆盖卡里测试 3（密钥标签分组与计数）与 D 的密钥详情：
// 未归入项目组置顶且计数正确、N=0 不出现该组、>20 才显示搜索框、页面不含密钥明文。
func TestSecretsTabGroupsAndKeyDetail(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	cookie, csrf := "ia-secrets-session", "ia-secrets-csrf"
	sessions.Lock()
	sessions.m[cookie] = adminSession{csrf: csrf, created: time.Now(), last: time.Now()}
	sessions.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := st.DB.Exec(`INSERT INTO namespaces(id,name,created_at) VALUES('ia-zz','zz-project',?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`INSERT INTO clients(id,ns,name,token_hash,scopes,created_at) VALUES('ia-cz','zz-project','zz-client',?, 'secrets:list,fetch', ?)`, []byte("ia-cz"), now); err != nil {
		t.Fatal(err)
	}
	newSecret := func(ns, label string) string {
		m, err := s.save(SecretRequest{NS: ns, Label: label, Provider: "generic", Type: "token", Value: "SWSV-SECRETS-SENTINEL", Bindings: Binding{Hosts: []string{"example.com"}, NoClientAccess: true}}, false, "")
		if err != nil {
			t.Fatal(err)
		}
		return m.ID
	}
	unassigned := newSecret(unassignedNS, "ia-unassigned-key")
	inProject := newSecret("zz-project", "ia-project-key")
	disabled := newSecret("ns1", "ia-disabled-key")
	if _, err := st.DB.Exec(`UPDATE secrets SET status='revoked' WHERE id=?`, disabled); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`UPDATE secrets SET bindings=? WHERE id=?`, `{"hosts":["example.com"],"allowed_clients":["ia-cz"]}`, inProject); err != nil {
		t.Fatal(err)
	}

	body := adminPageRequest(s, cookie, http.MethodGet, "/admin/secrets", nil).Body.String()
	groups := []string{}
	for _, m := range panelH2RE.FindAllStringSubmatch(body, -1) {
		groups = append(groups, strings.TrimSpace(m[1]))
	}
	want := []string{"未归入项目 · 1", "ns1", "zz-project"}
	if len(groups) != len(want) {
		t.Fatalf("分组不正确：%v", groups)
	}
	for i := range want {
		if groups[i] != want[i] {
			t.Fatalf("分组顺序不正确：%v，期望 %v", groups, want)
		}
	}
	for _, needle := range []string{
		`href="/admin/secrets/` + unassigned + `"`,
		`href="/admin/secrets/` + inProject + `"`,
		"其他 · 尾号 ",
		"还没人能用",
		"1 个接入方",
		"已停用",
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("密钥标签缺少 %q", needle)
		}
	}
	if strings.Contains(body, `name="q"`) {
		t.Error("密钥数不超过 20 时不应显示搜索框")
	}
	if containsSentinel(body, "SWSV-SECRETS-SENTINEL") {
		t.Fatal("密钥标签泄漏了密钥值")
	}
	// 超过 20 个密钥才显示搜索框；按名称过滤只留下匹配的组。
	for i := 0; i < 19; i++ {
		newSecret("ns1", "ia-bulk-"+string(rune('a'+i)))
	}
	body = adminPageRequest(s, cookie, http.MethodGet, "/admin/secrets", nil).Body.String()
	if !strings.Contains(body, `name="q"`) {
		t.Error("密钥数超过 20 时应显示搜索框")
	}
	body = adminPageRequest(s, cookie, http.MethodGet, "/admin/secrets?q=ia-disabled", nil).Body.String()
	filtered := []string{}
	for _, m := range panelH2RE.FindAllStringSubmatch(body, -1) {
		filtered = append(filtered, strings.TrimSpace(m[1]))
	}
	if len(filtered) != 1 || filtered[0] != "ns1" {
		t.Fatalf("过滤后分组不正确：%v", filtered)
	}
	if strings.Contains(body, "ia-project-key") {
		t.Error("过滤后仍出现不匹配的密钥")
	}

	// 密钥详情（D）：名称、平台 · 尾号 · 指纹前 8 位、项目、谁在用、请求限制。
	var fingerprint string
	if err := st.DB.QueryRow(`SELECT fingerprint FROM secrets WHERE id=?`, inProject).Scan(&fingerprint); err != nil {
		t.Fatal(err)
	}
	detail := adminPageRequest(s, cookie, http.MethodGet, "/admin/secrets/"+inProject, nil).Body.String()
	for _, needle := range []string{
		"ia-project-key", "其他 · 尾号 ", "指纹 " + fingerprint[:8], "zz-project", "谁在用", "zz-client",
		`action="/admin/secrets/` + inProject + `/bindings"`,
		`action="/admin/secrets/` + inProject + `/clients"`,
		`href="/admin/secrets/` + inProject + `/rotate"`,
		`action="/admin/secrets/` + inProject + `/disable"`,
		"checked",
	} {
		if !strings.Contains(detail, needle) {
			t.Errorf("密钥详情缺少 %q", needle)
		}
	}
	if containsSentinel(detail, "SWSV-SECRETS-SENTINEL") {
		t.Fatal("密钥详情泄漏了密钥值")
	}
	unassignedDetail := adminPageRequest(s, cookie, http.MethodGet, "/admin/secrets/"+unassigned, nil).Body.String()
	if !strings.Contains(unassignedDetail, "未归入项目") || !strings.Contains(unassignedDetail, "任何接入方都用不了") {
		t.Error("未归入项目的密钥详情没有给出提示")
	}
	revokedDetail := adminPageRequest(s, cookie, http.MethodGet, "/admin/secrets/"+disabled, nil).Body.String()
	if !strings.Contains(revokedDetail, "已停用") || strings.Contains(revokedDetail, "/rotate") {
		t.Error("已停用的密钥详情状态或按钮不正确")
	}
	if w := adminPageRequest(s, cookie, http.MethodGet, "/admin/secrets/ia-no-such-key", nil); w.Code != http.StatusNotFound {
		t.Errorf("不存在的密钥详情应 404，实际 %d", w.Code)
	}
}

// TestAdminLegacyRedirects 覆盖卡里测试 1 的 303 映射（A3/A4）：
// 登录后与 /admin/ 落到密钥标签；旧「高级 / 所有密钥 / 接入项目」地址各自落到新页；
// 未登录访问 /admin/ 仍先跳登录页。
func TestAdminLegacyRedirects(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	cookie, csrf := "ia-redirect-session", "ia-redirect-csrf"
	sessions.Lock()
	sessions.m[cookie] = adminSession{csrf: csrf, created: time.Now(), last: time.Now()}
	sessions.Unlock()
	for _, tc := range []struct{ path, location string }{
		{"/admin/", "/admin/secrets"},

		{"/admin/advanced", "/admin/secrets"},
		{"/admin/advanced/secrets", "/admin/secrets"},
		{"/admin/advanced/secrets?ns=ns1&provider=generic", "/admin/secrets"},
		{"/admin/namespaces", "/admin/projects"},
		{"/admin/clients", "/admin/projects"},
		{"/admin/quick/project", "/admin/secrets/new"},
		{"/admin/quick/project?project=ui-test&client=default", "/admin/secrets/new"},
	} {
		w := adminPageRequest(s, cookie, http.MethodGet, tc.path, nil)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != tc.location {
			t.Errorf("%s 应 303 到 %s，实际 %d %q", tc.path, tc.location, w.Code, w.Header().Get("Location"))
		}
	}
	// /admin（无斜杠）由 ServeMux 先 301 到 /admin/，再走上面的 303。
	if w := adminPageRequest(s, cookie, http.MethodGet, "/admin", nil); w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != "/admin/" {
		t.Errorf("/admin 应先 301 到 /admin/，实际 %d %q", w.Code, w.Header().Get("Location"))
	}
	if anon := adminPageRequest(s, "ia-no-such-session", http.MethodGet, "/admin/", nil); anon.Code != http.StatusSeeOther || anon.Header().Get("Location") != "/admin/login" {
		t.Errorf("未登录访问 /admin/ 应先跳登录页，实际 %d %q", anon.Code, anon.Header().Get("Location"))
	}
	password, totp, loginCSRF, csrfCookie := prepareAdminLogin(t, s, st)
	form := url.Values{"csrf": {loginCSRF}, "password": {password}, "totp": {totp}}
	r := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(csrfCookie)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/secrets" {
		t.Errorf("登录后应 303 到 /admin/secrets，实际 %d %q", w.Code, w.Header().Get("Location"))
	}
}

// TestNewSecretFlowAndProjectMove 覆盖卡里测试 4（新建 → 给谁用：预选、放进项目后再跳添加接入方）
// 与 D 的「移到项目…」（含移出二次确认、换项目后仍能取出明文）。
func TestNewSecretFlowAndProjectMove(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	cookie, csrf := "ia-new-session", "ia-new-csrf"
	sessions.Lock()
	sessions.m[cookie] = adminSession{csrf: csrf, created: time.Now(), last: time.Now()}
	sessions.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)
	for _, ns := range []string{"zz-project", "yy-project"} {
		if _, err := st.DB.Exec(`INSERT INTO namespaces(id,name,created_at) VALUES(?,?,?)`, ns, ns, now); err != nil {
			t.Fatal(err)
		}
	}
	moveToken := "swsv_move-client-token"
	sum := sha256.Sum256([]byte(moveToken))
	if _, err := st.DB.Exec(`INSERT INTO clients(id,ns,name,token_hash,scopes,created_at) VALUES('ia-cmove','yy-project','move-client',?, 'secrets:list,resolve,fetch', ?)`, sum[:], now); err != nil {
		t.Fatal(err)
	}
	const sentinel = "SWSV-NEW-SECRET-SENTINEL"
	readNS := func(id string) string {
		t.Helper()
		var ns string
		if err := st.DB.QueryRow(`SELECT ns FROM secrets WHERE id=?`, id).Scan(&ns); err != nil {
			t.Fatal(err)
		}
		return ns
	}
	readBinding := func(id string) Binding {
		t.Helper()
		var raw string
		if err := st.DB.QueryRow(`SELECT bindings FROM secrets WHERE id=?`, id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var bd Binding
		if err := json.Unmarshal([]byte(raw), &bd); err != nil {
			t.Fatal(err)
		}
		return bd
	}

	// ?project= 预选 + C 的提示文案
	form := adminPageRequest(s, cookie, http.MethodGet, "/admin/secrets/new?project=zz-project", nil).Body.String()
	if !strings.Contains(form, `<option value="zz-project" selected>`) || !strings.Contains(form, "不选就先放在「未归入项目」，任何接入方都用不了") {
		t.Fatalf("新建密钥页未按 ?project= 预选或缺少提示文案")
	}

	// 建到项目里：成功页给「给谁用 →」和「完成」两条路
	w := adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/new", url.Values{"csrf": {csrf}, "provider": {"github-pat"}, "label": {"ia-new-in-project"}, "value": {sentinel}, "project": {"zz-project"}})
	if w.Code != http.StatusOK || containsSentinel(w.Body.String(), sentinel) {
		t.Fatalf("建密钥失败或回显了密钥值: %d", w.Code)
	}
	var inProject string
	if err := st.DB.QueryRow(`SELECT id FROM secrets WHERE label='ia-new-in-project'`).Scan(&inProject); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"已保存", "ia-new-in-project", "尾号 ", "放在项目 zz-project", "/admin/projects/zz-project/clients/new?secret=" + inProject, `href="/admin/secrets/` + inProject + `">完成</a>`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("成功页缺少 %q", want)
		}
	}

	// 未归入项目：成功页的「给谁用 →」先去放进项目
	w = adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/new", url.Values{"csrf": {csrf}, "provider": {"github-pat"}, "label": {"ia-new-unassigned"}, "value": {sentinel}})
	if w.Code != http.StatusOK {
		t.Fatalf("建未归入项目的密钥失败: %d", w.Code)
	}
	var loose string
	if err := st.DB.QueryRow(`SELECT id FROM secrets WHERE label='ia-new-unassigned'`).Scan(&loose); err != nil {
		t.Fatal(err)
	}
	if readNS(loose) != unassignedNS {
		t.Fatalf("不选项目时应放在未归入项目，实际 %s", readNS(loose))
	}
	if !strings.Contains(w.Body.String(), "/admin/secrets/"+loose+"/project?next=clients") {
		t.Error("未归入项目的成功页没有指向放进项目")
	}

	// 放进项目页：列出现有项目 + 新建项目；选完把密钥移入并跳到添加接入方
	picker := adminPageRequest(s, cookie, http.MethodGet, "/admin/secrets/"+loose+"/project?next=clients", nil).Body.String()
	for _, want := range []string{"放进项目", "zz-project", "yy-project", `href="/admin/projects/new"`} {
		if !strings.Contains(picker, want) {
			t.Errorf("放进项目页缺少 %q", want)
		}
	}
	if strings.Contains(picker, "移出到「未归入项目」") {
		t.Error("未归入项目的密钥不该出现「移出到未归入项目」")
	}
	moved := adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/"+loose+"/project", url.Values{"csrf": {csrf}, "to": {"zz-project"}, "next": {"clients"}})
	if moved.Code != http.StatusSeeOther || moved.Header().Get("Location") != "/admin/projects/zz-project/clients/new?secret="+loose {
		t.Fatalf("放进项目后应跳到添加接入方并预勾该密钥，实际 %d %q", moved.Code, moved.Header().Get("Location"))
	}
	if readNS(loose) != "zz-project" {
		t.Fatalf("密钥没有移入项目：%s", readNS(loose))
	}
	if bd := readBinding(loose); !bd.NoClientAccess || len(bd.AllowedClients) != 0 {
		t.Fatalf("刚放进项目的密钥不应授权给任何人：%+v", bd)
	}

	// 添加接入方（F）：带 ?secret= 只预勾该密钥；不带参数时默认一个都不勾。
	checkedSecrets := regexp.MustCompile(`name="secret" value="[^"]+" checked>`)
	addOne := adminPageRequest(s, cookie, http.MethodGet, "/admin/projects/zz-project/clients/new?secret="+loose, nil).Body.String()
	if got := checkedSecrets.FindAllString(addOne, -1); len(got) != 1 || !strings.Contains(got[0], loose) {
		t.Errorf("?secret= 应只预勾该密钥，实际 %v", got)
	}
	addAll := adminPageRequest(s, cookie, http.MethodGet, "/admin/projects/zz-project/clients/new", nil).Body.String()
	if got := checkedSecrets.FindAllString(addAll, -1); len(got) != 0 {
		t.Errorf("不带 ?secret= 时应默认不勾任何密钥（F），实际 %v", got)
	}
	if !strings.Contains(addAll, "仅代发") || strings.Contains(addAll, "<details>") || strings.Contains(addAll, "高级") {
		t.Error("添加接入方页应把权限做成两段式、不再有「高级」折叠区（F）")
	}

	// D 的「移到项目…」：移出到未归入项目要二次确认
	movePage := adminPageRequest(s, cookie, http.MethodGet, "/admin/secrets/"+inProject+"/project", nil).Body.String()
	if !strings.Contains(movePage, "移出到「未归入项目」") {
		t.Error("已在项目里的密钥应能移出到未归入项目")
	}
	noConfirm := adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/"+inProject+"/project", url.Values{"csrf": {csrf}, "to": {unassignedNS}})
	if noConfirm.Code != http.StatusOK || !strings.Contains(noConfirm.Body.String(), "确认移出") {
		t.Fatalf("移出应先二次确认，实际 %d", noConfirm.Code)
	}
	if readNS(inProject) != "zz-project" {
		t.Fatal("没有二次确认就把密钥移出了")
	}
	confirmed := adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/"+inProject+"/project", url.Values{"csrf": {csrf}, "to": {unassignedNS}, "confirm": {"yes"}})
	if confirmed.Code != http.StatusSeeOther || confirmed.Header().Get("Location") != "/admin/secrets/"+inProject {
		t.Fatalf("确认移出后应回密钥详情，实际 %d %q", confirmed.Code, confirmed.Header().Get("Location"))
	}
	if readNS(inProject) != unassignedNS {
		t.Fatalf("确认后仍未移出：%s", readNS(inProject))
	}
	if bd := readBinding(inProject); !bd.NoClientAccess || len(bd.AllowedClients) != 0 {
		t.Fatalf("移出时应同时撤掉所有接入方的授权：%+v", bd)
	}

	// 换到另一个项目后仍能取出明文（证明按新项目重新加密正确）
	if _, err := st.DB.Exec(`UPDATE secrets SET bindings=? WHERE id=?`, `{"hosts":["api.github.com"],"allow_resolve":true}`, inProject); err != nil {
		t.Fatal(err)
	}
	move2 := adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/"+inProject+"/project", url.Values{"csrf": {csrf}, "to": {"yy-project"}})
	if move2.Code != http.StatusSeeOther {
		t.Fatalf("换项目失败：%d %s", move2.Code, move2.Body.String())
	}
	if readNS(inProject) != "yy-project" {
		t.Fatalf("换项目后 ns 不对：%s", readNS(inProject))
	}
	grant := adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/"+inProject+"/bindings", url.Values{"csrf": {csrf}, "hosts": {"api.github.com"}, "allowed_clients": {"ia-cmove"}, "allow_resolve": {"on"}})
	if grant.Code != http.StatusSeeOther {
		t.Fatalf("授权失败：%d", grant.Code)
	}
	code, out := request(t, s, moveToken, http.MethodPost, "/v1/resolve", `{"secret":"vault:yy-project/`+inProject+`"}`)
	if code != http.StatusOK || !strings.Contains(out, sentinel) {
		t.Fatalf("换项目后取不出明文（重加密有误）：%d %s", code, out)
	}

	// 目标项目不存在 → 400；密钥不存在 → 404
	if bad := adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/"+inProject+"/project", url.Values{"csrf": {csrf}, "to": {"no-such-project"}}); bad.Code != http.StatusBadRequest {
		t.Errorf("不存在的项目应 400，实际 %d", bad.Code)
	}
	if missing := adminPageRequest(s, cookie, http.MethodGet, "/admin/secrets/ia-no-such-key/project", nil); missing.Code != http.StatusNotFound {
		t.Errorf("不存在的密钥应 404，实际 %d", missing.Code)
	}
}

// TestClientDetailPermissions 覆盖卡里测试 6（接入方详情 G）：
// 开关保存准确、跨项目 404、改权限两个方向、不得把未授权密钥的 AllowResolve 改成 true、
// CIDR 非法 400 且库不变、重新生成后旧令牌失效新令牌可用。
func TestClientDetailPermissions(t *testing.T) {
	s, st, token, _ := testServer(t, "secrets:list,fetch")
	cookie, csrf := "ia-client-session", "ia-client-csrf"
	sessions.Lock()
	sessions.m[cookie] = adminSession{csrf: csrf, created: time.Now(), last: time.Now()}
	sessions.Unlock()
	newSecret := func(label string) string {
		m, err := s.save(SecretRequest{NS: "ns1", Label: label, Provider: "generic", Type: "token", Value: "SWSV-CLIENT-SENTINEL", Bindings: Binding{Hosts: []string{"example.com"}, NoClientAccess: true}}, false, "")
		if err != nil {
			t.Fatal(err)
		}
		return m.ID
	}
	authorized := newSecret("ia-client-authorized")
	other := newSecret("ia-client-other")
	readBinding := func(id string) Binding {
		t.Helper()
		var raw string
		if err := st.DB.QueryRow(`SELECT bindings FROM secrets WHERE id=?`, id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var bd Binding
		if err := json.Unmarshal([]byte(raw), &bd); err != nil {
			t.Fatal(err)
		}
		return bd
	}
	type clientState struct{ scopes, cidrs, note string }
	readClient := func() clientState {
		t.Helper()
		var v clientState
		if err := st.DB.QueryRow(`SELECT scopes,cidrs,note FROM clients WHERE id='c1'`).Scan(&v.scopes, &v.cidrs, &v.note); err != nil {
			t.Fatal(err)
		}
		return v
	}
	// 只授权 kAuth 给 c1，另一个密钥保持「还没人能用」。
	if w := adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/"+authorized+"/clients", url.Values{"csrf": {csrf}, "client": {"c1"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("授权失败：%d", w.Code)
	}

	page := adminPageRequest(s, cookie, http.MethodGet, "/admin/projects/ns1/clients/c1", nil).Body.String()
	for _, want := range []string{"接入方详情", "test", "仅代发", "状态", "能用哪些密钥", `value="` + authorized + `" checked>`, `value="` + other + `">`, `‹ ns1`, `class="tabbar"`} {
		if !strings.Contains(page, want) {
			t.Errorf("接入方详情缺少 %q", want)
		}
	}
	// 跨项目 URL 一律 404。
	if w := adminPageRequest(s, cookie, http.MethodGet, "/admin/projects/other/clients/c1", nil); w.Code != http.StatusNotFound {
		t.Errorf("跨项目接入方详情应 404，实际 %d", w.Code)
	}
	if w := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/other/clients/c1", url.Values{"csrf": {csrf}, "note": {"x"}}); w.Code != http.StatusNotFound {
		t.Errorf("跨项目保存应 404，实际 %d", w.Code)
	}

	// 改成「可取明文」：对它已授权的密钥打开 AllowResolve，未授权的不动。
	w := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/ns1/clients/c1", url.Values{"csrf": {csrf}, "note": {"Hark 改 DNS 用"}, "cidrs": {"10.0.0.1"}, "permission": {"resolve"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("保存接入方失败：%d %s", w.Code, w.Body.String())
	}
	saved := readClient()
	if !hasScope(saved.scopes, "resolve") || saved.cidrs != "10.0.0.1/32" || saved.note != "Hark 改 DNS 用" {
		t.Fatalf("权限/来源 IP/备注没有保存正确：%+v", saved)
	}
	if bd := readBinding(authorized); !bd.AllowResolve {
		t.Fatalf("已授权的密钥应打开 AllowResolve：%+v", bd)
	}
	if bd := readBinding(other); bd.AllowResolve {
		t.Fatalf("未授权给它的密钥不得打开 AllowResolve：%+v", bd)
	}

	// 改回「仅代发」：去掉 resolve scope。
	w = adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/ns1/clients/c1", url.Values{"csrf": {csrf}, "note": {"Hark 改 DNS 用"}, "cidrs": {"10.0.0.1"}, "permission": {"fetch"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("改回仅代发失败：%d", w.Code)
	}
	if saved = readClient(); hasScope(saved.scopes, "resolve") {
		t.Fatalf("改回仅代发应去掉 resolve scope：%q", saved.scopes)
	}

	// CIDR 非法 → 400 且库不变。
	before := readClient()
	if w := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/ns1/clients/c1", url.Values{"csrf": {csrf}, "note": {"被改坏了"}, "cidrs": {"not-a-cidr"}, "permission": {"resolve"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("非法 CIDR 应 400，实际 %d", w.Code)
	}
	if afterState := readClient(); afterState != before {
		t.Fatalf("非法 CIDR 改动了库：%+v → %+v", before, afterState)
	}

	// 自定义权限：只读展示，不允许被改。
	if _, err := st.DB.Exec(`UPDATE clients SET scopes='secrets:list,secrets:write,fetch' WHERE id='c1'`); err != nil {
		t.Fatal(err)
	}
	custom := adminPageRequest(s, cookie, http.MethodGet, "/admin/projects/ns1/clients/c1", nil).Body.String()
	if !strings.Contains(custom, "自定义") || strings.Contains(custom, `name="permission"`) {
		t.Fatal("自定义权限应只读展示，不出选择框")
	}
	if w := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/ns1/clients/c1", url.Values{"csrf": {csrf}, "permission": {"resolve"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("自定义权限保存应成功但不动权限：%d", w.Code)
	}
	if saved = readClient(); saved.scopes != "secrets:list,secrets:write,fetch" {
		t.Fatalf("自定义权限被改动了：%q", saved.scopes)
	}

	// 能用哪些密钥：开关保存准确。
	if w := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/ns1/clients/c1/secrets", url.Values{"csrf": {csrf}}); w.Code != http.StatusSeeOther {
		t.Fatalf("清空授权失败：%d", w.Code)
	}
	after := adminPageRequest(s, cookie, http.MethodGet, "/admin/projects/ns1/clients/c1", nil).Body.String()
	if strings.Count(after, " checked>") != 0 {
		t.Fatalf("清空授权后详情页仍显示勾选：%s", after)
	}
	if w := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/ns1/clients/c1/secrets", url.Values{"csrf": {csrf}, "secret": {authorized}}); w.Code != http.StatusSeeOther {
		t.Fatalf("重新授权失败：%d", w.Code)
	}
	after = adminPageRequest(s, cookie, http.MethodGet, "/admin/projects/ns1/clients/c1", nil).Body.String()
	if strings.Count(after, " checked>") != 1 || !strings.Contains(after, `value="`+authorized+`" checked>`) {
		t.Fatalf("授权开关保存不准确")
	}

	// 重新生成通行证：旧令牌立即失效，新令牌可用。
	regen := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/ns1/clients/c1/regenerate", url.Values{"csrf": {csrf}})
	if regen.Code != http.StatusOK {
		t.Fatalf("重新生成通行证失败：%d %s", regen.Code, regen.Body.String())
	}
	newToken := regexp.MustCompile(`swsv_[A-Za-z0-9_-]{43}`).FindString(regen.Body.String())
	if newToken == "" || newToken == token {
		t.Fatalf("重新生成没有给出新令牌：%q", regen.Body.String()[:120])
	}
	if code, _ := request(t, s, token, http.MethodGet, "/v1/secrets?ns=ns1", ""); code != http.StatusUnauthorized {
		t.Errorf("旧令牌应立即失效，实际 %d", code)
	}
	if code, out := request(t, s, newToken, http.MethodGet, "/v1/secrets?ns=ns1", ""); code != http.StatusOK {
		t.Errorf("新令牌应可用，实际 %d %s", code, out)
	}

	// 停用后回到它的详情页。
	disabled := adminPageRequest(s, cookie, http.MethodPost, "/admin/clients/c1/disable", url.Values{"csrf": {csrf}})
	if disabled.Code != http.StatusSeeOther || disabled.Header().Get("Location") != "/admin/projects/ns1/clients/c1" {
		t.Fatalf("停用后应回接入方详情，实际 %d %q", disabled.Code, disabled.Header().Get("Location"))
	}
	var flag int
	if err := st.DB.QueryRow(`SELECT disabled FROM clients WHERE id='c1'`).Scan(&flag); err != nil || flag != 1 {
		t.Fatalf("接入方没有停用：%v %d", err, flag)
	}
}

// TestProjectTabAndSecretEntryPoints 覆盖 E：项目列表右上角「＋」、项目详情两组与「放入密钥」，
// 以及放入密钥的三条入口（新建密钥带 from=project / 从未归入项目里选 / 生成录入链接）。
func TestProjectTabAndSecretEntryPoints(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	cookie, csrf := "ia-proj-session", "ia-proj-csrf"
	sessions.Lock()
	sessions.m[cookie] = adminSession{csrf: csrf, created: time.Now(), last: time.Now()}
	sessions.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := st.DB.Exec(`INSERT INTO namespaces(id,name,created_at,description) VALUES('ia-ns','ia-proj',?,'给博客用的 DNS 令牌')`, now); err != nil {
		t.Fatal(err)
	}
	m, err := s.save(SecretRequest{NS: "ia-proj", Label: "博客 DNS 令牌", Provider: "cloudflare-token", Type: "token", Value: "SWSV-PROJ-SENTINEL", Bindings: Binding{Hosts: []string{"api.cloudflare.com"}, NoClientAccess: true}}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`INSERT INTO clients(id,ns,name,token_hash,scopes,created_at,note) VALUES('ia-pc','ia-proj','blog-worker',?, 'secrets:list,fetch', ?, 'Hark 的博客')`, []byte("ia-pc"), now); err != nil {
		t.Fatal(err)
	}

	list := adminPageRequest(s, cookie, http.MethodGet, "/admin/projects", nil).Body.String()
	for _, want := range []string{`aria-label="新建项目"`, "ia-proj", "1 密钥 · 1 接入方", `class="tabbar"`} {
		if !strings.Contains(list, want) {
			t.Errorf("项目列表缺少 %q", want)
		}
	}
	if strings.Contains(list, `class="bar"`) {
		t.Error("项目列表不该再用吸底按钮")
	}

	detail := adminPageRequest(s, cookie, http.MethodGet, "/admin/projects/ia-proj", nil).Body.String()
	for _, want := range []string{
		"给博客用的 DNS 令牌",
		`href="/admin/secrets/` + m.ID + `"`,
		`href="/admin/projects/ia-proj/secrets/add"`,
		"放入密钥",
		`href="/admin/projects/ia-proj/clients/ia-pc"`,
		"仅代发 · 来源 IP 不限 · 正常",
		`href="/admin/projects/ia-proj/clients/new">添加接入方</a>`,
		`href="/admin/projects/ia-proj/edit">编辑</a>`,
		`‹ 项目`,
	} {
		if !strings.Contains(detail, want) {
			t.Errorf("项目详情缺少 %q", want)
		}
	}
	if strings.Contains(detail, "/admin/clients/ia-pc/disable") {
		t.Error("项目详情不该在接入方行上放停用按钮")
	}

	add := adminPageRequest(s, cookie, http.MethodGet, "/admin/projects/ia-proj/secrets/add", nil).Body.String()
	for _, want := range []string{"放入密钥", "/admin/secrets/new?project=ia-proj&from=project", "/admin/projects/ia-proj/secrets/import", "/admin/projects/ia-proj/intents/new"} {
		if !strings.Contains(add, want) {
			t.Errorf("放入密钥页缺少 %q", want)
		}
	}
	imp := adminPageRequest(s, cookie, http.MethodGet, "/admin/projects/ia-proj/secrets/import", nil).Body.String()
	if !strings.Contains(imp, "从未归入项目里选") || strings.Contains(imp, "未关联") {
		t.Errorf("移入页标题/文案不对：%s", imp[:120])
	}

	// 生成录入链接：项目固定，结果页叫「录入链接」，库里 10 分钟有效。
	form := adminPageRequest(s, cookie, http.MethodGet, "/admin/projects/ia-proj/intents/new", nil).Body.String()
	if !strings.Contains(form, "生成录入链接") || strings.Contains(form, `name="ns"`) {
		t.Error("项目内生成录入链接不该再让用户选项目")
	}
	res := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/ia-proj/intents/new", url.Values{"csrf": {csrf}, "label": {"ia-intent"}})
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "录入链接") || !strings.Contains(res.Body.String(), "/i/") {
		t.Fatalf("生成录入链接失败：%d %s", res.Code, res.Body.String())
	}
	var intentNS, expires string
	if err := st.DB.QueryRow(`SELECT ns,expires_at FROM intents WHERE label='ia-intent'`).Scan(&intentNS, &expires); err != nil {
		t.Fatal(err)
	}
	deadline, err := time.Parse(time.RFC3339, expires)
	if err != nil || intentNS != "ia-proj" || time.Until(deadline) > 11*time.Minute {
		t.Fatalf("录入链接参数不对：ns=%q expires=%q err=%v", intentNS, expires, err)
	}

	// 编辑项目简介
	edit := adminPageRequest(s, cookie, http.MethodGet, "/admin/projects/ia-proj/edit", nil).Body.String()
	if !strings.Contains(edit, "给博客用的 DNS 令牌") || !strings.Contains(edit, "编辑项目") {
		t.Error("编辑项目页没有带出原简介")
	}
	if w := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/ia-proj/description", url.Values{"csrf": {csrf}, "description": {"改过的简介"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("保存简介失败：%d", w.Code)
	}
	var description string
	if err := st.DB.QueryRow(`SELECT description FROM namespaces WHERE name='ia-proj'`).Scan(&description); err != nil || description != "改过的简介" {
		t.Fatalf("简介没有保存：%q %v", description, err)
	}

	// 术语：本卡新页面不得出现禁用词
	for _, page := range []string{list, detail, add, imp, edit} {
		visible := regexp.MustCompile(`(?is)<[^>]*>`).ReplaceAllString(page, " ")
		for _, bad := range []string{"未关联", "客户端", "命名空间", "接入项目", "高级"} {
			if strings.Contains(visible, bad) {
				t.Errorf("项目页出现禁用词 %q", bad)
			}
		}
	}
	if containsSentinel(detail, "SWSV-PROJ-SENTINEL") || containsSentinel(add, "SWSV-PROJ-SENTINEL") {
		t.Fatal("项目页泄漏了密钥值")
	}
}

// TestAddClientFormAndPermissions 覆盖 F（设计稿 ⑤）：两段式权限、来源 IP 直显、无 ?secret= 默认不勾、
// 至少选一个的校验保留、语义与结果页不变。
func TestAddClientFormAndPermissions(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	cookie, csrf := "ia-add-session", "ia-add-csrf"
	sessions.Lock()
	sessions.m[cookie] = adminSession{csrf: csrf, created: time.Now(), last: time.Now()}
	sessions.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := st.DB.Exec(`INSERT INTO namespaces(id,name,created_at) VALUES('ia-add','ia-add',?)`, now); err != nil {
		t.Fatal(err)
	}
	m, err := s.save(SecretRequest{NS: "ia-add", Label: "ia-add-key", Provider: "github-pat", Type: "token", Value: "SWSV-ADD-SENTINEL", Bindings: Binding{Hosts: []string{"api.github.com"}, NoClientAccess: true}}, false, "")
	if err != nil {
		t.Fatal(err)
	}

	form := adminPageRequest(s, cookie, http.MethodGet, "/admin/projects/ia-add/clients/new", nil).Body.String()
	for _, want := range []string{"谁来调用", "能用哪些密钥", "权限", "仅代发", "可取明文", "来源 IP（可选）", `name="cidrs"`, `name="allow_resolve" value="" checked`} {
		if !strings.Contains(form, want) {
			t.Errorf("添加接入方页缺少 %q", want)
		}
	}
	for _, bad := range []string{"<details>", "高级"} {
		if strings.Contains(form, bad) {
			t.Errorf("添加接入方页仍有 %q（F 要求取消高级折叠区）", bad)
		}
	}
	checkedSecrets := regexp.MustCompile(`name="secret" value="[^"]+" checked>`)
	if got := checkedSecrets.FindAllString(form, -1); len(got) != 0 {
		t.Errorf("没有 ?secret= 时应默认不勾任何密钥，实际 %v", got)
	}
	if !strings.Contains(form, `name="secret" value="`+m.ID+`"`) {
		t.Error("能用哪些密钥没有列出本项目密钥")
	}

	// 至少选一个的校验保留。
	if w := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/ia-add/clients/new", url.Values{"csrf": {csrf}, "name": {"no-secret"}}); w.Code != http.StatusBadRequest {
		t.Errorf("没选密钥应 400，实际 %d", w.Code)
	}

	// 仅代发（默认）：新接入方没有 resolve scope。
	if w := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/ia-add/clients/new", url.Values{"csrf": {csrf}, "name": {"ia-fetch"}, "secret": {m.ID}}); w.Code != http.StatusOK {
		t.Fatalf("创建接入方失败：%d %s", w.Code, w.Body.String())
	}
	var scopes string
	if err := st.DB.QueryRow(`SELECT scopes FROM clients WHERE ns='ia-add' AND name='ia-fetch'`).Scan(&scopes); err != nil {
		t.Fatal(err)
	}
	if hasScope(scopes, "resolve") {
		t.Errorf("默认应只给代发：%q", scopes)
	}

	// 可取明文 + 来源 IP：scope 与规范化后的 CIDR 都写对。
	res := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/ia-add/clients/new", url.Values{"csrf": {csrf}, "name": {"ia-resolve"}, "secret": {m.ID}, "allow_resolve": {"on"}, "cidrs": {"10.0.0.1"}})
	if res.Code != http.StatusOK {
		t.Fatalf("创建可取明文接入方失败：%d", res.Code)
	}
	var cidrs string
	if err := st.DB.QueryRow(`SELECT scopes,cidrs FROM clients WHERE ns='ia-add' AND name='ia-resolve'`).Scan(&scopes, &cidrs); err != nil {
		t.Fatal(err)
	}
	if !hasScope(scopes, "resolve") || cidrs != "10.0.0.1/32" {
		t.Errorf("可取明文/来源 IP 没有写对：scopes=%q cidrs=%q", scopes, cidrs)
	}
	// 结果页（一次性通行证）不变：令牌只出现一次，且带上来源 IP。
	body := res.Body.String()
	token := regexp.MustCompile(`swsv_[A-Za-z0-9_-]{43}`).FindString(body)
	if token == "" || !strings.Contains(body, "SWSV_TOKEN="+token) {
		t.Error("结果页应显示一次性令牌（SV-04 结果页不变）")
	}
	if !strings.Contains(body, "来源 IP：10.0.0.1/32") {
		t.Error("结果页应显示规范化后的来源 IP")
	}
	if containsSentinel(body, "SWSV-ADD-SENTINEL") {
		t.Fatal("结果页泄漏了密钥值")
	}
}

// panelForbiddenWords 是卡里术语表：面板可见文本里不得出现这些词。
var panelForbiddenWords = []string{"命名空间", "客户端", "client", "高级", "意图", "intent", "接入项目", "未关联", "绑定"}

func panelVisibleText(html string) string {
	return regexp.MustCompile(`(?is)<[^>]*>`).ReplaceAllString(html, " ")
}

// TestPanelTerminologySweep 覆盖卡里测试 2：遍历全部管理 GET 页（含详情、设置、结果、录入链接页），
// 可见文本不含禁用词表里任何一个（只查可见文本，不查 URL 和 name 属性）。
func TestPanelTerminologySweep(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := st.DB.Exec(`INSERT INTO namespaces(id,name,created_at,description) VALUES('ia-w','ia-word',?,'简介')`, now); err != nil {
		t.Fatal(err)
	}
	m, err := s.save(SecretRequest{NS: "ia-word", Label: "ia-word-key", Provider: "github-pat", Type: "token", Value: "SWSV-WORD-SENTINEL", Bindings: Binding{Hosts: []string{"api.github.com"}, AllowedClients: []string{"c1"}}}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`INSERT INTO clients(id,ns,name,token_hash,scopes,created_at) VALUES('ia-wc','ia-word','word-helper',?, 'secrets:list,fetch', ?)`, []byte("ia-wc"), now); err != nil {
		t.Fatal(err)
	}
	intentToken := "ia-word-intent-token"
	sum := sha256.Sum256([]byte(intentToken))
	if _, err := st.DB.Exec(`INSERT INTO intents(token_hash,ns,label,expires_at) VALUES(?,?,?,?)`, sum[:], "ia-word", "ia-word", time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := "ia-word-session", "ia-word-csrf"
	setSession := func(mustChange, enrollOnly bool) {
		sessions.Lock()
		sessions.m[cookie] = adminSession{csrf: csrf, created: time.Now(), last: time.Now(), mustChange: mustChange, enrollOnly: enrollOnly}
		sessions.Unlock()
	}
	pages := []string{
		"/admin/login", "/admin/settings", "/admin/audit", "/admin/intents/new",
		"/admin/secrets", "/admin/secrets/new", "/admin/secrets/" + m.ID, "/admin/secrets/" + m.ID + "/bindings",
		"/admin/secrets/" + m.ID + "/rotate", "/admin/secrets/" + m.ID + "/project",
		"/admin/projects", "/admin/projects/new", "/admin/projects/ia-word", "/admin/projects/ia-word/edit",
		"/admin/projects/ia-word/secrets/add", "/admin/projects/ia-word/secrets/import",
		"/admin/projects/ia-word/intents/new", "/admin/projects/ia-word/clients/new",
		"/admin/projects/ia-word/clients/ia-wc", "/i/" + intentToken,
	}
	for _, path := range pages {
		setSession(false, false)
		w := adminPageRequest(s, cookie, http.MethodGet, path, nil)
		if path == "/admin/login" {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			w = httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
		}
		if w.Code != http.StatusOK {
			t.Fatalf("%s status=%d", path, w.Code)
		}
		visible := panelVisibleText(w.Body.String())
		for _, bad := range panelForbiddenWords {
			if strings.Contains(visible, bad) {
				t.Errorf("%s 的可见文本出现禁用词 %q", path, bad)
			}
		}
	}
	// 受限会话的两个页面也要过一遍（先补一条 admins 行，否则 enroll 页取不到状态会 500）。
	if _, err := st.DB.Exec(`INSERT INTO admins(id,password_hash,password_salt,totp_secret,created_at,totp_enrolled,must_change_password) VALUES(1,X'00',X'00',X'00',?,0,1)`, now); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path                   string
		mustChange, enrollOnly bool
	}{{"/admin/password", true, true}, {"/admin/totp/enroll", false, true}} {
		// adminSession 每次都会按库里的 must_change_password 重新判定，两个页面的前置条件不同。
		flag := 0
		if tc.mustChange {
			flag = 1
		}
		if _, err := st.DB.Exec(`UPDATE admins SET must_change_password=? WHERE id=1`, flag); err != nil {
			t.Fatal(err)
		}
		setSession(tc.mustChange, tc.enrollOnly)
		w := adminPageRequest(s, cookie, http.MethodGet, tc.path, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s status=%d", tc.path, w.Code)
		}
		visible := panelVisibleText(w.Body.String())
		for _, bad := range panelForbiddenWords {
			if strings.Contains(visible, bad) {
				t.Errorf("%s 的可见文本出现禁用词 %q", tc.path, bad)
			}
		}
	}
}

// TestTabBarAndFormPageTraversal 覆盖卡里测试 1 的后半段：标签页都有标签栏且当前项唯一，
// 新建 / 添加 / 编辑类页面不显示标签栏且顶栏是「取消」+ 标题。
func TestTabBarAndFormPageTraversal(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	now := time.Now().UTC().Format(time.RFC3339)
	m, err := s.save(SecretRequest{NS: "ia-tab", Label: "ia-tab-key", Provider: "generic", Type: "token", Value: "SWSV-TAB-SENTINEL", Bindings: Binding{Hosts: []string{"example.com"}, NoClientAccess: true}}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`INSERT INTO clients(id,ns,name,token_hash,scopes,created_at) VALUES('ia-tc','ia-tab','tab-client',?, 'secrets:list,fetch', ?)`, []byte("ia-tc"), now); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := "ia-tab-session", "ia-tab-csrf"
	sessions.Lock()
	sessions.m[cookie] = adminSession{csrf: csrf, created: time.Now(), last: time.Now()}
	sessions.Unlock()
	currentRE := regexp.MustCompile(`aria-current="page"`)
	for _, path := range []string{"/admin/secrets", "/admin/projects", "/admin/audit", "/admin/settings", "/admin/secrets/" + m.ID, "/admin/projects/ia-tab", "/admin/projects/ia-tab/clients/ia-tc"} {
		body := adminPageRequest(s, cookie, http.MethodGet, path, nil).Body.String()
		if !strings.Contains(body, `class="tabbar"`) {
			t.Errorf("%s 是标签页，必须有标签栏", path)
		}
		if n := len(currentRE.FindAllString(body, -1)); n > 1 {
			t.Errorf("%s 的当前标签不唯一（%d 个）", path, n)
		}
	}
	for _, path := range []string{
		"/admin/secrets/new", "/admin/projects/new", "/admin/projects/ia-tab/clients/new",
		"/admin/projects/ia-tab/edit", "/admin/projects/ia-tab/secrets/add",
		"/admin/projects/ia-tab/secrets/import", "/admin/projects/ia-tab/intents/new",
		"/admin/secrets/" + m.ID + "/rotate", "/admin/secrets/" + m.ID + "/bindings", "/admin/secrets/" + m.ID + "/project",
	} {
		body := adminPageRequest(s, cookie, http.MethodGet, path, nil).Body.String()
		if strings.Contains(body, `class="tabbar"`) {
			t.Errorf("%s 是表单页，不该有标签栏", path)
		}
		if !strings.Contains(body, `>取消</a>`) || !strings.Contains(body, `class="page-title"`) {
			t.Errorf("%s 顶栏应是「取消」+ 标题", path)
		}
	}
}

// TestExplicitEmptyDeniesEveryClient 覆盖卡里测试 5 的显式空语义：关掉全部授权后，
// 连另一个未授权的接入方也拿不到（不是「空 = 项目内所有人都能用」）。
func TestExplicitEmptyDeniesEveryClient(t *testing.T) {
	s, st, tokenA, _ := testServer(t, "secrets:list,fetch")
	cookie, csrf := "ia-empty-session", "ia-empty-csrf"
	sessions.Lock()
	sessions.m[cookie] = adminSession{csrf: csrf, created: time.Now(), last: time.Now()}
	sessions.Unlock()
	tokenB := "swsv_second-client-token"
	sum := sha256.Sum256([]byte(tokenB))
	if _, err := st.DB.Exec(`INSERT INTO clients(id,ns,name,token_hash,scopes,created_at) VALUES('ia-cb','ns1','second',?, 'secrets:list,fetch', ?)`, sum[:], time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	m, err := s.save(SecretRequest{NS: "ns1", Label: "ia-empty-key", Provider: "generic", Type: "token", Value: "SWSV-EMPTY-SENTINEL", Bindings: Binding{Hosts: []string{"example.com"}, NoClientAccess: true}}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	fetch := func(token string) int {
		t.Helper()
		code, _ := request(t, s, token, http.MethodPost, "/v1/fetch", `{"secret":"vault:ns1/`+m.ID+`","method":"GET","url":"https://example.com/"}`)
		return code
	}
	if w := adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/"+m.ID+"/clients", url.Values{"csrf": {csrf}, "client": {"c1"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("授权失败：%d", w.Code)
	}
	// 关掉最后一个授权 → 显式空。
	if w := adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/"+m.ID+"/clients", url.Values{"csrf": {csrf}}); w.Code != http.StatusSeeOther {
		t.Fatalf("清空授权失败：%d", w.Code)
	}
	var raw string
	if err := st.DB.QueryRow(`SELECT bindings FROM secrets WHERE id=?`, m.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var bd Binding
	if err := json.Unmarshal([]byte(raw), &bd); err != nil {
		t.Fatal(err)
	}
	if len(bd.AllowedClients) != 0 || !bd.NoClientAccess {
		t.Fatalf("关掉最后一个授权必须写成显式空：%+v", bd)
	}
	if code := fetch(tokenA); code != http.StatusForbidden {
		t.Errorf("被撤权的接入方应 403，实际 %d", code)
	}
	if code := fetch(tokenB); code != http.StatusForbidden {
		t.Errorf("另一个未授权的接入方也应 403（显式空不是「所有人都能用」），实际 %d", code)
	}
}

// failingRows 给 authorizeProjectSecrets 注入结果集读取失败（I1）。
type failingRows struct {
	scanErr, errErr error
	// id/bindings 是给出一行「有效数据」用的：这样「吞掉 rows.Err」不会因为下游解析失败
	// 而仍然报 500，测试才能真正抓到被吞掉的错误。
	id, bindings string
	calls        int
}

func (f *failingRows) Next() bool { f.calls++; return f.calls == 1 }
func (f *failingRows) Scan(dest ...any) error {
	if f.scanErr != nil {
		return f.scanErr
	}
	for i, d := range dest {
		s, ok := d.(*string)
		if !ok {
			continue
		}
		if i == 0 {
			*s = f.id
		} else {
			*s = f.bindings
		}
	}
	return nil
}
func (f *failingRows) Err() error   { return f.errErr }
func (f *failingRows) Close() error { return nil }

// TestLegacyFixesRollbackGiteaPortAndUpgradePolling 覆盖卡里测试 9：
// I1 结果集读取失败要冒泡且事务回滚、I2 Gitea 带端口的使用范围保留端口、I3 upgrade.sh 的 healthz 轮询。
func TestLegacyFixesRollbackGiteaPortAndUpgradePolling(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list")
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := st.DB.Exec(`INSERT INTO namespaces(id,name,created_at) VALUES('ia-fix','ia-fix',?)`, now); err != nil {
		t.Fatal(err)
	}
	m, err := s.save(SecretRequest{NS: "ia-fix", Label: "ia-fix-key", Provider: "generic", Type: "token", Value: "SWSV-FIX-SENTINEL", Bindings: Binding{Hosts: []string{"example.com"}, NoClientAccess: true}}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf := "ia-fix-session", "ia-fix-csrf"
	sessions.Lock()
	sessions.m[cookie] = adminSession{csrf: csrf, created: time.Now(), last: time.Now()}
	sessions.Unlock()
	readBinding := func(id string) Binding {
		t.Helper()
		var raw string
		if err := st.DB.QueryRow(`SELECT bindings FROM secrets WHERE id=?`, id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var bd Binding
		if err := json.Unmarshal([]byte(raw), &bd); err != nil {
			t.Fatal(err)
		}
		return bd
	}

	// I1：rows.Scan / rows.Err 出错必须返回错误，并让事务回滚。
	for _, tc := range []struct {
		name string
		rows *failingRows
		only string
	}{
		{"scan", &failingRows{scanErr: errors.New("injected scan failure")}, ""},
		{"err", &failingRows{errErr: errors.New("injected rows.Err failure"), id: "ia-stub-client", bindings: `{"hosts":["example.com"],"no_client_access":true}`}, ""},
		// 只让第二个结果集（密钥列表）失败：两条 rows.Scan / rows.Err 路径都要能被这条测试抓住。
		{"clients-err", &failingRows{errErr: errors.New("injected rows.Err failure"), id: "ia-stub-client"}, "FROM clients"},
		{"secrets-scan", &failingRows{scanErr: errors.New("injected scan failure")}, "id,bindings"},
		{"secrets-err", &failingRows{errErr: errors.New("injected rows.Err failure"), id: "ia-fix-key", bindings: `{"hosts":["example.com"],"no_client_access":true}`}, "id,bindings"},
	} {
		orig := authorizeRowsQuery
		authorizeRowsQuery = func(tx *sql.Tx, query string, args ...any) (rowScanner, error) {
			if tc.only == "" || strings.Contains(query, tc.only) {
				return tc.rows, nil
			}
			return orig(tx, query, args...)
		}
		w := adminPageRequest(s, cookie, http.MethodPost, "/admin/projects/ia-fix/clients/new", url.Values{"csrf": {csrf}, "name": {"ia-fix-" + tc.name}, "secret": {m.ID}})
		authorizeRowsQuery = orig
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("%s：结果集读取失败应返回 500，实际 %d", tc.name, w.Code)
		}
		var n int
		if err := st.DB.QueryRow(`SELECT count(*) FROM clients WHERE ns='ia-fix'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("%s：事务没有回滚，接入方被建出来了", tc.name)
		}
		if bd := readBinding(m.ID); !bd.NoClientAccess || len(bd.AllowedClients) != 0 {
			t.Fatalf("%s：授权被改动了：%+v", tc.name, bd)
		}
	}

	// I2：Gitea 自建地址带非默认端口时保留端口；默认端口不写进使用范围。
	create := func(label, address string) Binding {
		t.Helper()
		w := adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/new", url.Values{"csrf": {csrf}, "provider": {"gitea-token"}, "label": {label}, "value": {"SWSV-FIX-SENTINEL"}, "gitea_address": {address}})
		if w.Code != http.StatusOK {
			t.Fatalf("%s 建密钥失败：%d %s", address, w.Code, w.Body.String())
		}
		var id string
		if err := st.DB.QueryRow(`SELECT id FROM secrets WHERE label=?`, label).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return readBinding(id)
	}
	if bd := create("ia-gitea-port", "https://git.example.com:3000"); len(bd.Hosts) != 1 || bd.Hosts[0] != "git.example.com:3000" {
		t.Fatalf("带端口的 Gitea 地址应保留端口：%v", bd.Hosts)
	}
	if bd := create("ia-gitea-plain", "https://git.example.com"); len(bd.Hosts) != 1 || bd.Hosts[0] != "git.example.com" {
		t.Fatalf("默认端口的 Gitea 地址不该写端口：%v", bd.Hosts)
	}

	// I3：upgrade.sh 重启后最多轮询 15 秒，超时非零退出，其余步骤不变。
	script, err := os.ReadFile("../../deploy/upgrade.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	for _, want := range []string{"systemctl restart sws-vault", "healthz=http://192.168.20.132:9531/healthz", "for _ in $(seq 1 15); do", "sleep 1", "healthz 在 15 秒内没有就绪", `curl --fail --silent --show-error "$healthz"`} {
		if !strings.Contains(text, want) {
			t.Errorf("upgrade.sh 缺少 %q", want)
		}
	}
	if !strings.Contains(text, `backup.sh" --apply`) || !strings.Contains(text, `install -m 0755 "$src" "$bin"`) || !strings.Contains(text, "systemctl --no-pager --full status sws-vault") {
		t.Error("upgrade.sh 的其它步骤被改动了")
	}
}
