package api

import (
	"encoding/json"
	"net/http"
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
		"通用 · 尾号 ",
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
		"ia-project-key", "通用 · 尾号 ", "指纹 " + fingerprint[:8], "zz-project", "谁在用", "zz-client",
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
