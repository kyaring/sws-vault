package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"github.com/kyaring/sws-vault/internal/auth"
	"github.com/kyaring/sws-vault/internal/panel"
	"html/template"

	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type adminSession struct {
	csrf          string
	created, last time.Time
}

var sessions = struct {
	sync.Mutex
	m map[string]adminSession
}{m: map[string]adminSession{}}

type loginAttempt struct {
	failures          int
	lockedUntil, last time.Time
}

var loginAttempts = struct {
	sync.Mutex
	m map[string]loginAttempt
}{m: map[string]loginAttempt{}}
var memoryCleanupOnce sync.Once
var loginBackoff = struct {
	sync.Mutex
	failures int
	last     time.Time
}{}

func globalLoginBackoff(now time.Time) time.Duration {
	loginBackoff.Lock()
	defer loginBackoff.Unlock()
	if now.Sub(loginBackoff.last) > 15*time.Minute {
		loginBackoff.failures = 0
	}
	loginBackoff.failures++
	loginBackoff.last = now
	delays := []time.Duration{100 * time.Millisecond, 250 * time.Millisecond, 500 * time.Millisecond, time.Second}
	idx := loginBackoff.failures - 1
	if idx >= len(delays) {
		idx = len(delays) - 1
	}
	return delays[idx]
}

func startMemoryCleanup() {
	memoryCleanupOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for now := range ticker.C {
				cleanupMemoryState(now)
			}
		}()
	})
}
func cleanupMemoryState(now time.Time) {
	sessions.Lock()
	for token, v := range sessions.m {
		if now.Sub(v.last) > 15*time.Minute || now.Sub(v.created) >= 8*time.Hour {
			delete(sessions.m, token)
		}
	}
	sessions.Unlock()
	rateState.Lock()
	for id, v := range rateState.m {
		if now.Sub(v.last) > 2*time.Minute {
			delete(rateState.m, id)
		}
	}
	rateState.Unlock()
	loginAttempts.Lock()
	for ip, v := range loginAttempts.m {
		if now.Sub(v.last) > 15*time.Minute && !now.Before(v.lockedUntil) {
			delete(loginAttempts.m, ip)
		}
	}
	loginAttempts.Unlock()
}

func (s *Server) adminHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/admin/login" {
		s.adminLogin(w, r)
		return
	}
	if r.URL.Path == "/admin/intents/new" {
		s.adminIntentNew(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/admin/clients/") && strings.HasSuffix(r.URL.Path, "/disable") {
		s.adminDisableClient(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/admin/secrets/") && strings.HasSuffix(r.URL.Path, "/rotate") {
		s.adminRotateSecret(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/admin/secrets/") && strings.HasSuffix(r.URL.Path, "/disable") {
		s.adminDisableSecret(w, r)
		return
	}
	if r.URL.Path == "/admin/namespaces" {
		s.adminNamespaces(w, r)
		return
	}
	if r.URL.Path == "/admin/clients" {
		s.adminClients(w, r)
		return
	}
	if r.URL.Path == "/admin/audit" {
		s.adminAudit(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/admin/secrets/") && strings.HasSuffix(r.URL.Path, "/bindings") {
		s.adminBindings(w, r)
		return
	}
	if r.URL.Path == "/admin/logout" {
		s.adminLogout(w, r)
		return
	}
	if r.URL.Path == "/admin/secrets/new" {
		s.adminNewSecret(w, r)
		return
	}
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	nsFilter := r.URL.Query().Get("ns")
	providerFilter := r.URL.Query().Get("provider")
	query := `SELECT id,ns,label,provider,type,preview,fingerprint,status,bindings,last_used_at FROM secrets WHERE 1=1`
	args := []any{}
	if nsFilter != "" {
		query += " AND ns=?"
		args = append(args, nsFilter)
	}
	if providerFilter != "" {
		query += " AND provider=?"
		args = append(args, providerFilter)
	}
	query += " ORDER BY created_at DESC LIMIT 200"
	rows, e := s.S.DB.Query(query, args...)
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	defer rows.Close()
	type item struct{ ID, NS, Label, Provider, Type, Preview, Fingerprint, Status, Bindings, LastUsed string }
	var items []item
	for rows.Next() {
		var v item
		if rows.Scan(&v.ID, &v.NS, &v.Label, &v.Provider, &v.Type, &v.Preview, &v.Fingerprint, &v.Status, &v.Bindings, &v.LastUsed) == nil {
			var bd Binding
			if json.Unmarshal([]byte(v.Bindings), &bd) == nil {
				bd.Username = mask(bd.Username)
				safe, _ := json.Marshal(bd)
				v.Bindings = string(safe)
			}
			items = append(items, v)
		}
	}
	data := struct {
		CSRF     string
		Items    []item
		NS       string
		Provider string
	}{sess.csrf, items, nsFilter, providerFilter}
	const page = `<!doctype html><html lang="zh"><meta charset="utf-8"><title>SWS Vault</title><h1>SWS Vault 管理面板</h1><p><a href="/admin/secrets/new">录入凭据</a> · <a href="/admin/namespaces">命名空间</a> · <a href="/admin/clients">客户端</a> · <a href="/admin/audit">审计事件</a> · <a href="/admin/intents/new">一次性录入链接</a></p><form method="get" action="/admin/"><label>命名空间<input name="ns" value="{{.NS}}"></label><label>平台<input name="provider" value="{{.Provider}}"></label><button>筛选</button></form><form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>退出</button></form><table><tr><th>ID</th><th>命名空间</th><th>标签</th><th>平台</th><th>预览</th><th>指纹</th><th>状态</th><th>绑定策略</th><th>最近使用</th></tr>{{range .Items}}<tr><td>{{.ID}} <a href="/admin/secrets/{{.ID}}/bindings">绑定</a> <a href="/admin/secrets/{{.ID}}/rotate">轮换</a><form method="post" action="/admin/secrets/{{.ID}}/disable" style="display:inline"><input type="hidden" name="csrf" value="{{$.CSRF}}"><button>停用</button></form></td><td>{{.NS}}</td><td>{{.Label}}</td><td>{{.Provider}}</td><td>{{.Preview}}</td><td>{{.Fingerprint}}</td><td>{{.Status}}</td><td>{{.Bindings}}</td><td>{{.LastUsed}}</td></tr>{{end}}</table></html>`
	render(w, page, data)
}
func (s *Server) adminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			errOut(w, 500, "internal error")
			return
		}
		csrf := base64.RawURLEncoding.EncodeToString(b)
		http.SetCookie(w, &http.Cookie{Name: "sv_login_csrf", Value: csrf, Path: "/admin", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: strings.HasPrefix(s.C.PublicBaseURL, "https://")})
		render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><title>登录</title><h1>SWS Vault 登录</h1><form method="post"><input type="hidden" name="csrf" value="`+template.HTMLEscapeString(csrf)+`"><label>密码 <input type="password" name="password" autocomplete="current-password" required></label><label>TOTP <input name="totp" inputmode="numeric" pattern="[0-9]{6}" required></label><button>登录</button></form></html>`, nil)
		return
	}
	if r.Method != http.MethodPost {
		errOut(w, 405, "method not allowed")
		return
	}
	_ = r.ParseForm()
	ck, e := r.Cookie("sv_login_csrf")
	if e != nil || subtle.ConstantTimeCompare([]byte(ck.Value), []byte(r.Form.Get("csrf"))) != 1 {
		errOut(w, 403, "csrf rejected")
		return
	}
	_, _ = s.S.DB.Exec(`CREATE TABLE IF NOT EXISTS admin_state(id INTEGER PRIMARY KEY CHECK(id=1),failed_count INTEGER NOT NULL DEFAULT 0,locked_until TEXT NOT NULL DEFAULT "",last_totp_step INTEGER NOT NULL DEFAULT -1)`)
	ip := s.sourceIP(r)
	if s.loginLocked(ip) {
		s.audit("admin", "", "login", "", "", "locked", s.sourceIP(r))
		errOut(w, 429, "login temporarily locked")
		return
	}
	var stored, salt, secret []byte
	e = s.S.DB.QueryRow(`SELECT password_hash,password_salt,totp_secret FROM admins WHERE id=1`).Scan(&stored, &salt, &secret)
	if e != nil {
		s.loginFailure(ip)
		s.audit("admin", "", "login", "", "", "failed", s.sourceIP(r))
		errOut(w, 401, "invalid credentials")
		return
	}
	got, e := auth.HashPassword(r.Form.Get("password"), salt)
	if e != nil || subtle.ConstantTimeCompare(got, stored) != 1 {
		s.loginFailure(ip)
		s.audit("admin", "", "login", "", "", "failed", s.sourceIP(r))
		errOut(w, 401, "invalid credentials")
		return
	}
	var last int64 = -1
	_ = s.S.DB.QueryRow(`SELECT last_totp_step FROM admin_state WHERE id=1`).Scan(&last)
	step, ok := auth.VerifyTOTP(secret, r.Form.Get("totp"), time.Now(), last)
	if !ok {
		s.loginFailure(ip)
		s.audit("admin", "", "login", "", "", "failed", s.sourceIP(r))
		errOut(w, 401, "invalid credentials")
		return
	}
	loginAttempts.Lock()
	delete(loginAttempts.m, ip)
	loginAttempts.Unlock()
	_, _ = s.S.DB.Exec(`INSERT INTO admin_state(id,failed_count,locked_until,last_totp_step) VALUES(1,0,'',?) ON CONFLICT(id) DO UPDATE SET failed_count=0,locked_until='',last_totp_step=excluded.last_totp_step`, step)
	token := make([]byte, 32)
	if _, e = rand.Read(token); e != nil {
		errOut(w, 500, "internal error")
		return
	}
	raw := base64.RawURLEncoding.EncodeToString(token)
	csrfB := make([]byte, 32)
	_, _ = rand.Read(csrfB)
	sess := adminSession{csrf: base64.RawURLEncoding.EncodeToString(csrfB), created: time.Now(), last: time.Now()}
	sessions.Lock()
	sessions.m[raw] = sess
	sessions.Unlock()
	s.audit("admin", "", "login", "", "", "ok", s.sourceIP(r))
	http.SetCookie(w, &http.Cookie{Name: "sws_admin", Value: raw, Path: "/admin", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: strings.HasPrefix(s.C.PublicBaseURL, "https://"), MaxAge: 28800})
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}
func (s *Server) loginLocked(ip string) bool {
	now := time.Now()
	cleanupMemoryState(now)
	loginAttempts.Lock()
	defer loginAttempts.Unlock()
	a := loginAttempts.m[ip]
	if !now.Before(a.lockedUntil) {
		a.lockedUntil = time.Time{}
		if a.failures >= 5 {
			a.failures = 0
		}
	}
	a.last = now
	loginAttempts.m[ip] = a
	return now.Before(a.lockedUntil)
}
func (s *Server) loginFailure(ip string) {
	now := time.Now()
	loginAttempts.Lock()
	a := loginAttempts.m[ip]
	a.failures++
	a.last = now
	if a.failures >= 5 {
		a.lockedUntil = now.Add(15 * time.Minute)
	}
	loginAttempts.m[ip] = a
	loginAttempts.Unlock()
	time.Sleep(globalLoginBackoff(now))
}
func (s *Server) adminSession(w http.ResponseWriter, r *http.Request) (adminSession, bool) {
	ck, e := r.Cookie("sws_admin")
	if e != nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return adminSession{}, false
	}
	sessions.Lock()
	defer sessions.Unlock()
	v, ok := sessions.m[ck.Value]
	now := time.Now()
	if !ok || now.Sub(v.last) > 15*time.Minute || now.Sub(v.created) > 8*time.Hour {
		delete(sessions.m, ck.Value)
		http.SetCookie(w, &http.Cookie{Name: "sws_admin", Value: "", Path: "/admin", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return adminSession{}, false
	}
	v.last = now
	sessions.m[ck.Value] = v
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		if subtle.ConstantTimeCompare([]byte(r.Form.Get("csrf")), []byte(v.csrf)) != 1 {
			errOut(w, 403, "csrf rejected")
			return adminSession{}, false
		}
	}
	return v, true
}
func (s *Server) adminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errOut(w, 405, "method not allowed")
		return
	}
	sess, ok := s.adminSession(w, r)
	_ = sess
	if !ok {
		return
	}
	if ck, e := r.Cookie("sws_admin"); e == nil {
		sessions.Lock()
		delete(sessions.m, ck.Value)
		sessions.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "sws_admin", Value: "", Path: "/admin", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	s.audit("admin", "", "logout", "", "", "ok", s.sourceIP(r))
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}
func (s *Server) adminNewSecret(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	const form = `<!doctype html><html lang="zh"><meta charset="utf-8"><title>录入凭据</title><h1>录入凭据</h1><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>命名空间 <input name="ns" value="default" required></label><label>标签 <input name="label" required></label><label>平台 <select name="provider"><option>generic</option><option>cloudflare-token</option><option>cloudflare-global-key</option><option>github-pat</option><option>gitea-token</option></select></label><label>类型 <select name="type"><option>token</option><option>api_key</option><option>login</option><option>webhook</option><option>note</option></select></label><label>允许主机（逗号分隔） <input name="hosts" autocomplete="off"></label><label>自定义 Header 模板 JSON <input name="headers" autocomplete="off"></label><label>验证 URL / Gitea base_url <input name="base_url" autocomplete="off"></label><label>保存前验证 <input type="checkbox" name="verify"></label><label>允许私网 <input type="checkbox" name="allow_private"></label><label>允许 HTTP <input type="checkbox" name="allow_http"></label><label>用户名 <input name="username" autocomplete="off"></label><label>值 <input type="password" name="value" autocomplete="off" required></label><label>允许解析 <input type="checkbox" name="allow_resolve"></label><button>保存</button></form></html>`
	if r.Method == http.MethodGet {
		render(w, form, map[string]string{"CSRF": sess.csrf})
		return
	}
	if r.Method != http.MethodPost {
		errOut(w, 405, "method not allowed")
		return
	}
	_ = r.ParseForm()
	q := SecretRequest{NS: r.Form.Get("ns"), Label: r.Form.Get("label"), Provider: r.Form.Get("provider"), Type: r.Form.Get("type"), Username: r.Form.Get("username"), Value: r.Form.Get("value"), Bindings: Binding{AllowResolve: r.Form.Get("allow_resolve") == "on", AllowPrivate: r.Form.Get("allow_private") == "on", AllowHTTP: r.Form.Get("allow_http") == "on"}}
	for _, host := range strings.Split(r.Form.Get("hosts"), ",") {
		if host = strings.TrimSpace(host); host != "" {
			q.Bindings.Hosts = append(q.Bindings.Hosts, host)
		}
	}
	if raw := strings.TrimSpace(r.Form.Get("headers")); raw != "" {
		if json.Unmarshal([]byte(raw), &q.Bindings.Headers) != nil {
			errOut(w, 400, "invalid header templates")
			return
		}
	}
	if q.Provider == "gitea-token" && len(q.Bindings.Hosts) == 0 {
		if u, e := url.Parse(r.Form.Get("base_url")); e == nil && u.Host != "" {
			q.Bindings.Hosts = []string{u.Host}
		}
	}
	if q.NS == "" || q.Label == "" || q.Value == "" {
		errOut(w, 400, "invalid request")
		return
	}
	if r.Form.Get("verify") == "on" {
		if e := s.verifySecret(q, r.Form.Get("base_url")); e != nil {
			errOut(w, 400, e.Error())
			return
		}
	}
	if _, e := s.save(q, false, ""); e != nil {
		errOut(w, 500, "internal error")
		return
	}
	s.audit("admin", q.NS, "write", "", "", "ok", s.sourceIP(r))
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}
func render(w http.ResponseWriter, src string, data any) { panel.Render(w, src, data) }
