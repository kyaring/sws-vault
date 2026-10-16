package api

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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

	// 添加接入方：带 ?secret= 只预勾该密钥；不带参数保持原有默认（全勾）
	addOne := adminPageRequest(s, cookie, http.MethodGet, "/admin/projects/zz-project/clients/new?secret="+loose, nil).Body.String()
	if strings.Count(addOne, " checked>") != 1 || !strings.Contains(addOne, `value="`+loose+`" checked>`) {
		t.Errorf("?secret= 预勾不正确")
	}
	addAll := adminPageRequest(s, cookie, http.MethodGet, "/admin/projects/zz-project/clients/new", nil).Body.String()
	if strings.Count(addAll, " checked>") != 2 {
		t.Errorf("不带 ?secret= 时应保持原有默认（全部勾选），实际 %d 个", strings.Count(addAll, " checked>"))
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
