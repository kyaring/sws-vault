package api

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kyaring/sws-vault/web"
)

var (
	inlineStyleRE   = regexp.MustCompile(`(?i)\bstyle\s*=`)
	scriptElementRE = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script\s*>`)
	inlineEventRE   = regexp.MustCompile(`(?i)<[^>]+\son[a-z]+\s*=`)
	adminAssetRefRE = regexp.MustCompile(`/admin/assets/[A-Za-z0-9._-]+`)
)

func hasInlineScript(body string) bool {
	for _, match := range scriptElementRE.FindAllStringSubmatch(body, -1) {
		if !strings.Contains(strings.ToLower(match[1]), "src=") || strings.TrimSpace(match[2]) != "" {
			return true
		}
	}
	return false
}

func TestInlineEventCheckIgnoresEscapedUserText(t *testing.T) {
	if inlineEventRE.MatchString(`&lt;img src=x onerror=alert(1)&gt;`) {
		t.Fatal("escaped user text was mistaken for an inline event attribute")
	}
	if !inlineEventRE.MatchString(`<img src=x onerror=alert(1)>`) {
		t.Fatal("actual inline event attribute was not detected")
	}
}

func TestAllPanelHTMLHasNoInlineCodeAndCSPUnchanged(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list,secrets:write,resolve,fetch")
	cookie, csrf := "ui-panel-session", "ui-panel-csrf"
	setSession := func(mustChange, enrollOnly bool) {
		sessions.Lock()
		sessions.m[cookie] = adminSession{csrf: csrf, created: time.Now(), last: time.Now(), mustChange: mustChange, enrollOnly: enrollOnly}
		sessions.Unlock()
	}
	setSession(false, false)
	// Create an intent solely in the isolated test database so intent.go's GET page is covered.
	intentToken := "ui-test-intent-token"
	intentHash := sha256.Sum256([]byte(intentToken))
	_, err := st.DB.Exec(`INSERT INTO intents(token_hash,ns,label,expires_at,used_at) VALUES(?,?,?,?, '')`, intentHash[:], "ns1", "ui-test", time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{
		"/admin/login", "/admin/", "/admin/secrets/new", "/admin/quick/project",
		"/admin/quick/project?project=ui-test&client=default", "/admin/advanced", "/admin/advanced/secrets",
		"/admin/namespaces", "/admin/clients", "/admin/audit", "/admin/intents/new",
		"/admin/secrets/missing/bindings", "/admin/not-a-route", "/i/" + intentToken,
	}
	for _, path := range paths {
		setSession(false, false)
		w := adminPageRequest(s, cookie, http.MethodGet, path, nil)
		if path == "/admin/login" {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			w = httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
		}
		if w.Code != http.StatusOK && w.Code != http.StatusNotFound {
			t.Fatalf("%s status=%d body=%s", path, w.Code, w.Body.String())
		}
		if path == "/admin/" && (!strings.Contains(w.Body.String(), `<svg`) || !strings.Contains(w.Body.String(), `>新建</b>`) || !strings.Contains(w.Body.String(), `>接入项目</b>`)) {
			t.Errorf("dashboard action cards missing SVG/copy")
		}
		if path == "/admin/login" || strings.HasPrefix(path, "/admin/") || path == "/admin/" || strings.HasPrefix(path, "/i/") {
			if !strings.Contains(w.Body.String(), `name="viewport" content="width=device-width,initial-scale=1"`) || !strings.Contains(w.Body.String(), `/admin/assets/admin.css`) {
				t.Errorf("%s missing viewport or admin.css", path)
			}
			body := w.Body.String()
			for _, assetPath := range adminAssetRefRE.FindAllString(body, -1) {
				assetReq := httptest.NewRequest(http.MethodGet, assetPath, nil)
				assetResp := httptest.NewRecorder()
				s.Handler().ServeHTTP(assetResp, assetReq)
				if assetResp.Code != http.StatusOK {
					t.Errorf("%s references %s but asset returned %d", path, assetPath, assetResp.Code)
				}
			}
			if (path == "/admin/clients" || path == "/admin/audit") && (!strings.Contains(body, `<thead>`) || !strings.Contains(body, `<tbody>`)) {
				t.Errorf("%s table missing thead/tbody", path)
			}
			if path == "/admin/clients" && !strings.Contains(body, `data-label="ID"`) {
				t.Errorf("%s table cells missing mobile data-label attributes", path)
			}
			if (path == "/admin/password" || path == "/admin/advanced" || path == "/admin/advanced/secrets") && strings.Contains(body, `action="/admin/logout"`) {
				t.Errorf("%s body contains logout form", path)
			}
			if (path == "/admin/clients" || path == "/admin/namespaces" || path == "/admin/intents/new") && strings.Contains(body, `class="bar"><button class="btn block"`) {
				t.Errorf("%s advanced action incorrectly uses sticky bar", path)
			}
			if path == "/admin/quick/project?project=ui-test&client=default" && (!strings.Contains(body, `class="back" href="/admin/quick/project">‹ 上一步`) || strings.Contains(body, `>返回上一步</a>`) || strings.Contains(body, `>取消</a>`)) {
				t.Errorf("quick project step 2 navigation not in top bar")
			}
			if path == "/admin/secrets/new" && (!strings.Contains(body, "粘贴后立即加密保存") || !strings.Contains(body, "不关联时，任何客户端都无法调用") || !strings.Contains(body, "只会发往这个域名") || !strings.Contains(body, `class="brand-cloudflare"`) || !strings.Contains(body, `>Cloudflare</b>`)) {
				t.Errorf("new secret page missing design copy/platform tiles")
			}

			if inlineStyleRE.MatchString(body) || strings.Contains(strings.ToLower(body), "<style") || hasInlineScript(body) || inlineEventRE.MatchString(body) {
				t.Errorf("%s contains inline style/script/event attribute", path)
			}
		}
		if got := w.Header().Get("Content-Security-Policy"); got != "default-src 'self'" {
			t.Errorf("%s CSP=%q", path, got)
		}
	}

	setSession(true, true)
	w := adminPageRequest(s, cookie, http.MethodGet, "/admin/password", nil)
	passwordHTML := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(passwordHTML, `name="viewport"`) || !strings.Contains(passwordHTML, `/admin/assets/admin.css`) || strings.Contains(passwordHTML, `action="/admin/logout"`) || inlineStyleRE.MatchString(passwordHTML) || hasInlineScript(passwordHTML) || inlineEventRE.MatchString(passwordHTML) {
		t.Fatalf("change-password page violates page shell/CSP constraints: status=%d", w.Code)
	}
	setSession(false, true)
	w = adminPageRequest(s, cookie, http.MethodGet, "/admin/totp/enroll", nil)
	if !strings.Contains(w.Body.String(), `name="viewport"`) || strings.Contains(w.Body.String(), `action="/admin/logout"`) || inlineStyleRE.MatchString(w.Body.String()) || hasInlineScript(w.Body.String()) || inlineEventRE.MatchString(w.Body.String()) {
		t.Fatalf("TOTP enrollment page violates page shell/CSP constraints: status=%d", w.Code)
	}

	setSession(false, false)
	w = adminPageRequest(s, cookie, http.MethodPost, "/admin/secrets/new", url.Values{
		"csrf": {csrf}, "provider": {"generic"}, "label": {"ui-test-secret"}, "value": {"fake-ui-test-value"}, "hosts": {"example.com"},
	})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `name="viewport"`) || inlineStyleRE.MatchString(w.Body.String()) || hasInlineScript(w.Body.String()) || inlineEventRE.MatchString(w.Body.String()) {
		t.Fatalf("saved page violates page shell/CSP constraints: status=%d", w.Code)
	}
	w = adminPageRequest(s, cookie, http.MethodPost, "/admin/quick/project", url.Values{"csrf": {csrf}, "project": {"ui-project"}, "client": {"ui-client"}})
	projectHTML := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(projectHTML, `class="secret"`) || !strings.Contains(projectHTML, `class="btn small secondary copy"`) || !strings.Contains(projectHTML, `class="note warn"`) || !strings.Contains(projectHTML, `class="hint">使用范围：`) || !strings.Contains(projectHTML, `name="viewport"`) || !strings.Contains(projectHTML, `/admin/assets/admin.css`) || inlineStyleRE.MatchString(projectHTML) || hasInlineScript(projectHTML) || inlineEventRE.MatchString(projectHTML) {
		t.Fatalf("project configuration page status=%d missing copy UI or contains inline code", w.Code)
	}

	css, err := web.Assets.ReadFile("admin.css")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(css), "a.primary") || !strings.Contains(string(css), ".bar .btn { flex: 1; }") || !strings.Contains(string(css), ".dot {") {
		t.Fatal("admin.css still contains conflicting a.primary selector")
	}
	// Admin HTML errors use the shell; API errors remain JSON.
	clientHTML := adminPageRequest(s, cookie, http.MethodGet, "/admin/clients", nil).Body.String()
	if !strings.Contains(clientHTML, `class="btn small danger"`) || strings.Contains(clientHTML, `class="bar"><button class="btn block">创建客户端`) {
		t.Fatalf("client page missing compact danger action or has sticky create action")
	}
	w = adminPageRequest(s, cookie, http.MethodGet, "/admin/not-a-route", nil)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), `class="appbar"`) || !strings.Contains(w.Body.String(), "找不到这个页面") || !strings.Contains(w.Body.String(), "<details>") || !strings.Contains(w.Body.String(), "技术详情") {
		t.Fatalf("admin 404 status=%d body=%s", w.Code, w.Body.String())
	}
	w = adminPageRequest(s, cookie, http.MethodPost, "/admin/quick/project", url.Values{"csrf": {csrf}, "project": {"INVALID NAME"}, "client": {"ui-client"}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `class="appbar"`) {
		t.Fatalf("admin 400 status=%d body=%s", w.Code, w.Body.String())
	}
	w = adminPageRequest(s, cookie, http.MethodPost, "/admin/namespaces", url.Values{"csrf": {"wrong-csrf"}, "name": {"ui-forbidden"}})
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `class="appbar"`) || !strings.Contains(w.Body.String(), "csrf rejected") {
		t.Fatalf("admin 403 status=%d body=%s", w.Code, w.Body.String())
	}
	apiReq := httptest.NewRequest(http.MethodGet, "/v1/secrets", nil)
	apiRes := httptest.NewRecorder()
	s.Handler().ServeHTTP(apiRes, apiReq)
	if apiRes.Code != http.StatusUnauthorized || !strings.Contains(apiRes.Header().Get("Content-Type"), "application/json") || !strings.Contains(apiRes.Body.String(), `"error"`) {
		t.Fatalf("API error changed: status=%d content-type=%q body=%s", apiRes.Code, apiRes.Header().Get("Content-Type"), apiRes.Body.String())
	}
}

func TestDashboardStatsAreReadOnlyAndAccurate(t *testing.T) {
	s, st, _, _ := testServer(t, "secrets:list,secrets:write,resolve")
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := st.DB.Exec(`INSERT INTO namespaces(id,name,created_at) VALUES('ui-ns2','ui-ns2',?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`INSERT INTO namespaces(id,name,created_at) VALUES('ui-ns-reserved','_x',?)`, now); err != nil {
		t.Fatal(err)
	}
	for _, q := range []SecretRequest{
		{NS: "ns1", Label: "ui-one", Provider: "generic", Type: "token", Value: "fake-one"},
		{NS: "ui-ns2", Label: "ui-two", Provider: "generic", Type: "token", Value: "fake-two"},
		{NS: unassignedNS, Label: "ui-three", Provider: "generic", Type: "token", Value: "fake-three"},
	} {
		q.Bindings = Binding{Hosts: []string{"example.com"}, AllowResolve: true}
		if _, err := s.save(q, false, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.save(SecretRequest{NS: "ns1", Label: "ui-disabled", Provider: "generic", Type: "token", Value: "fake-disabled", Bindings: Binding{Hosts: []string{"example.com"}, AllowResolve: true}}, false, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`UPDATE secrets SET status='disabled' WHERE label='ui-disabled'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`UPDATE secrets SET last_used_at=? WHERE label='ui-one'`, time.Now().Add(-5*time.Minute).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := "ui-stats-session", "ui-stats-csrf"
	sessions.Lock()
	sessions.m[cookie] = adminSession{csrf: csrf, created: time.Now(), last: time.Now()}
	sessions.Unlock()
	before := make(map[string]int64)
	for _, table := range []string{"secrets", "namespaces", "clients"} {
		var count int64
		if err := st.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		before[table] = count
	}
	w := adminPageRequest(s, cookie, http.MethodGet, "/admin/", nil)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "3 个有效密钥 · 2 个项目") || !strings.Contains(body, "最近一次调用 5 分钟前") || !strings.Contains(body, `class="badge">1</span>`) || !strings.Contains(body, "ui-ns2") || strings.Contains(body, "_x") || strings.Count(body, `class="dot"`) < 5 || !strings.Contains(body, "还没给任何项目，暂不可调用") {
		t.Fatalf("dashboard stats incorrect: status=%d body=%s", w.Code, body)
	}
	for table, expected := range before {
		var after int64
		if err := st.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&after); err != nil {
			t.Fatal(err)
		}
		if after != expected {
			t.Fatalf("dashboard mutated %s: before=%d after=%d", table, expected, after)
		}
	}
}
