package api

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"github.com/kyaring/sws-vault/internal/auth"
	vaultcrypto "github.com/kyaring/sws-vault/internal/crypto"
	"html/template"
	"net/http"
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

func (s *Server) adminHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/admin/login" {
		s.adminLogin(w, r)
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
	rows, e := s.S.DB.Query(`SELECT id,ns,label,provider,type,preview,fingerprint,status FROM secrets ORDER BY created_at DESC LIMIT 200`)
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	defer rows.Close()
	type item struct{ ID, NS, Label, Provider, Type, Preview, Fingerprint, Status string }
	var items []item
	for rows.Next() {
		var v item
		if rows.Scan(&v.ID, &v.NS, &v.Label, &v.Provider, &v.Type, &v.Preview, &v.Fingerprint, &v.Status) == nil {
			items = append(items, v)
		}
	}
	data := struct {
		CSRF  string
		Items []item
	}{sess.csrf, items}
	const page = `<!doctype html><html lang="zh"><meta charset="utf-8"><title>SWS Vault</title><h1>SWS Vault 管理面板</h1><p><a href="/admin/secrets/new">录入凭据</a></p><form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>退出</button></form><table><tr><th>命名空间</th><th>标签</th><th>平台</th><th>预览</th><th>指纹</th><th>状态</th></tr>{{range .Items}}<tr><td>{{.NS}}</td><td>{{.Label}}</td><td>{{.Provider}}</td><td>{{.Preview}}</td><td>{{.Fingerprint}}</td><td>{{.Status}}</td></tr>{{end}}</table></html>`
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
	if s.loginLocked() {
		errOut(w, 429, "login temporarily locked")
		return
	}
	var stored, salt, secret []byte
	e = s.S.DB.QueryRow(`SELECT password_hash,password_salt,totp_secret FROM admins WHERE id=1`).Scan(&stored, &salt, &secret)
	if e != nil {
		s.loginFailure()
		errOut(w, 401, "invalid credentials")
		return
	}
	got, e := pbkdf2.Key(sha256.New, r.Form.Get("password"), salt, 600000, 32)
	if e != nil || subtle.ConstantTimeCompare(got, stored) != 1 {
		s.loginFailure()
		errOut(w, 401, "invalid credentials")
		return
	}
	var last int64 = -1
	_ = s.S.DB.QueryRow(`SELECT last_totp_step FROM admin_state WHERE id=1`).Scan(&last)
	step, ok := auth.VerifyTOTP(secret, r.Form.Get("totp"), time.Now(), last)
	if !ok {
		s.loginFailure()
		errOut(w, 401, "invalid credentials")
		return
	}
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
	http.SetCookie(w, &http.Cookie{Name: "sws_admin", Value: raw, Path: "/admin", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: strings.HasPrefix(s.C.PublicBaseURL, "https://"), MaxAge: 28800})
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}
func (s *Server) loginLocked() bool {
	_, _ = s.S.DB.Exec(`CREATE TABLE IF NOT EXISTS admin_state(id INTEGER PRIMARY KEY CHECK(id=1),failed_count INTEGER NOT NULL DEFAULT 0,locked_until TEXT NOT NULL DEFAULT '',last_totp_step INTEGER NOT NULL DEFAULT -1)`)
	var until string
	e := s.S.DB.QueryRow(`SELECT locked_until FROM admin_state WHERE id=1`).Scan(&until)
	if e != nil {
		return false
	}
	t, e := time.Parse(time.RFC3339, until)
	return e == nil && time.Now().Before(t)
}
func (s *Server) loginFailure() {
	_, _ = s.S.DB.Exec(`CREATE TABLE IF NOT EXISTS admin_state(id INTEGER PRIMARY KEY CHECK(id=1),failed_count INTEGER NOT NULL DEFAULT 0,locked_until TEXT NOT NULL DEFAULT '',last_totp_step INTEGER NOT NULL DEFAULT -1)`)
	_, _ = s.S.DB.Exec(`INSERT INTO admin_state(id,failed_count,locked_until,last_totp_step) VALUES(1,1,'',-1) ON CONFLICT(id) DO UPDATE SET failed_count=failed_count+1,locked_until=CASE WHEN failed_count+1>=5 THEN ? ELSE locked_until END`, time.Now().Add(15*time.Minute).UTC().Format(time.RFC3339))
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
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}
func (s *Server) adminNewSecret(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	const form = `<!doctype html><html lang="zh"><meta charset="utf-8"><title>录入凭据</title><h1>录入凭据</h1><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>命名空间 <input name="ns" value="default" required></label><label>标签 <input name="label" required></label><label>平台 <select name="provider"><option>generic</option><option>cloudflare-token</option><option>cloudflare-global-key</option><option>github-pat</option><option>gitea-token</option></select></label><label>类型 <select name="type"><option>token</option><option>api_key</option><option>login</option><option>webhook</option><option>note</option></select></label><label>值 <input type="password" name="value" autocomplete="off" required></label><label>允许解析 <input type="checkbox" name="allow_resolve"></label><button>保存</button></form></html>`
	if r.Method == http.MethodGet {
		render(w, form, map[string]string{"CSRF": sess.csrf})
		return
	}
	if r.Method != http.MethodPost {
		errOut(w, 405, "method not allowed")
		return
	}
	_ = r.ParseForm()
	q := SecretRequest{NS: r.Form.Get("ns"), Label: r.Form.Get("label"), Provider: r.Form.Get("provider"), Type: r.Form.Get("type"), Value: r.Form.Get("value"), Bindings: Binding{AllowResolve: r.Form.Get("allow_resolve") == "on"}}
	if q.NS == "" || q.Label == "" || q.Value == "" {
		errOut(w, 400, "invalid request")
		return
	}
	if _, e := s.save(q, false, ""); e != nil {
		errOut(w, 500, "internal error")
		return
	}
	s.audit("admin", q.NS, "write", "", "", "ok", remoteIP(r))
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}
func render(w http.ResponseWriter, src string, data any) {
	t, e := template.New("page").Parse(src)
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if e = t.Execute(w, data); e != nil {
		return
	}
}

var _ = json.Valid
var _ = sql.ErrNoRows
var _ = vaultcrypto.KeySize
