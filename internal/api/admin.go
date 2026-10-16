package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"github.com/kyaring/sws-vault/internal/auth"
	"github.com/kyaring/sws-vault/internal/panel"
	stdhtml "html"
	"html/template"

	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"time"
)

type adminSession struct {
	csrf          string
	created, last time.Time
	enrollOnly    bool
	mustChange    bool
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
		if r.Method == http.MethodGet {
			if _, err := r.Cookie("sws_admin"); err == nil {
				if _, ok := s.adminSession(w, r); !ok {
					return
				}
			}
		}
		s.adminLogin(w, r)
		return
	}
	if r.URL.Path == "/admin/password" {
		s.adminChangePassword(w, r)
		return
	}
	if r.URL.Path == "/admin/totp/enroll" {
		s.adminEnrollTOTP(w, r)
		return
	}
	if r.URL.Path == "/admin/settings" {
		s.adminSettings(w, r)
		return
	}
	if r.URL.Path == "/admin/quick/project" {
		// A4：一步式「接入项目」不再有入口，GET 一律去新建密钥；POST 处理保留（SV-04 口径不变）。
		if r.Method == http.MethodGet {
			http.Redirect(w, r, "/admin/secrets/new", http.StatusSeeOther)
			return
		}
		s.adminQuickProject(w, r)
		return
	}
	if r.URL.Path == "/admin/advanced" {
		// A4：旧的「高级」入口删除，一律去密钥标签。
		http.Redirect(w, r, "/admin/secrets", http.StatusSeeOther)
		return
	}
	if r.URL.Path == "/admin/" || r.URL.Path == "/admin" {
		// A3：首页删除，登录后与 /admin/ 都落到密钥标签；未登录仍先跳登录页。
		if _, ok := s.adminSession(w, r); !ok {
			return
		}
		http.Redirect(w, r, "/admin/secrets", http.StatusSeeOther)
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
	if strings.HasPrefix(r.URL.Path, "/admin/secrets/") && strings.HasSuffix(r.URL.Path, "/clients") {
		s.adminSecretClients(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/admin/secrets/") && strings.HasSuffix(r.URL.Path, "/project") {
		s.adminSecretProject(w, r)
		return
	}
	if r.URL.Path == "/admin/namespaces" {
		s.adminNamespaces(w, r)
		return
	}
	if r.URL.Path == "/admin/projects" {
		s.adminProjects(w, r)
		return
	}
	if r.URL.Path == "/admin/projects/new" {
		s.adminProjectNew(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/admin/projects/") {
		s.adminProjectRoute(w, r)
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
	if r.URL.Path == "/admin/secrets" {
		s.adminSecrets(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/admin/secrets/") {
		s.adminSecretDetail(w, r)
		return
	}
	if _, ok := s.adminSession(w, r); !ok {
		return
	}
	if r.URL.Path == "/admin/advanced/secrets" {
		// A4：旧「所有密钥」页删除（宽表格和 bindings JSON 单元格一并去掉），一律去密钥标签。
		http.Redirect(w, r, "/admin/secrets", http.StatusSeeOther)
		return
	}
	adminErrOut(w, http.StatusNotFound, "not found")
}
func (s *Server) adminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			adminErrOut(w, 500, "internal error")
			return
		}
		csrf := base64.RawURLEncoding.EncodeToString(b)
		http.SetCookie(w, &http.Cookie{Name: "sv_login_csrf", Value: csrf, Path: "/admin", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: strings.HasPrefix(s.C.PublicBaseURL, "https://")})
		var enrolled int = 1
		_ = s.S.DB.QueryRow(`SELECT totp_enrolled FROM admins WHERE id=1`).Scan(&enrolled)
		totpField := `<label>验证码 <input name="totp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required></label>`
		if enrolled == 0 {
			totpField = ""
		}
		httpNote := ""
		if !strings.HasPrefix(s.C.PublicBaseURL, "https://") {
			httpNote = `<p class="note warn">明文 HTTP 只录测试密钥。</p>`
		}
		render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>登录</title><section class="auth"><div class="logo" aria-hidden="true"><svg viewBox="0 0 24 24" role="img"><path d="M12 2 4 5v6c0 5 3.4 9 8 11 4.6-2 8-6 8-11V5l-8-3Zm0 4 4 1.5V11c0 3-1.7 5.4-4 6.8-2.3-1.4-4-3.8-4-6.8V7.5L12 6Z" fill="currentColor"/></svg></div><h1>SWS Vault 登录</h1>`+httpNote+`<form method="post"><input type="hidden" name="csrf" value="`+template.HTMLEscapeString(csrf)+`"><label>密码 <input type="password" name="password" autocomplete="current-password" required></label>`+totpField+`<button>登录</button></form></section></html>`, nil)
		return
	}
	if r.Method != http.MethodPost {
		adminErrOut(w, 405, "method not allowed")
		return
	}
	_ = r.ParseForm()
	ck, e := r.Cookie("sv_login_csrf")
	if e != nil || subtle.ConstantTimeCompare([]byte(ck.Value), []byte(r.Form.Get("csrf"))) != 1 {
		adminErrOut(w, 403, "csrf rejected")
		return
	}
	_, _ = s.S.DB.Exec(`CREATE TABLE IF NOT EXISTS admin_state(id INTEGER PRIMARY KEY CHECK(id=1),failed_count INTEGER NOT NULL DEFAULT 0,locked_until TEXT NOT NULL DEFAULT "",last_totp_step INTEGER NOT NULL DEFAULT -1)`)
	ip := s.sourceIP(r)
	if s.loginLocked(ip) {
		s.audit("admin", "", "login", "", "", "locked", s.sourceIP(r))
		adminErrOut(w, 429, "login temporarily locked")
		return
	}
	var stored, salt, secret []byte
	var enrolled, mustChange int
	e = s.S.DB.QueryRow(`SELECT password_hash,password_salt,totp_secret,totp_enrolled,must_change_password FROM admins WHERE id=1`).Scan(&stored, &salt, &secret, &enrolled, &mustChange)
	if e != nil {
		s.loginFailure(ip)
		s.audit("admin", "", "login", "", "", "failed", s.sourceIP(r))
		adminErrOut(w, 401, "invalid credentials")
		return
	}
	got, e := auth.HashPassword(r.Form.Get("password"), salt)
	if e != nil || subtle.ConstantTimeCompare(got, stored) != 1 {
		s.loginFailure(ip)
		s.audit("admin", "", "login", "", "", "failed", s.sourceIP(r))
		adminErrOut(w, 401, "invalid credentials")
		return
	}
	var step int64 = -1
	if enrolled != 0 {
		var last int64 = -1
		_ = s.S.DB.QueryRow(`SELECT last_totp_step FROM admin_state WHERE id=1`).Scan(&last)
		var valid bool
		step, valid = auth.VerifyTOTP(secret, r.Form.Get("totp"), time.Now(), last)
		if !valid {
			s.loginFailure(ip)
			s.audit("admin", "", "login", "", "", "failed", s.sourceIP(r))
			adminErrOut(w, 401, "invalid credentials")
			return
		}
	}
	loginAttempts.Lock()
	delete(loginAttempts.m, ip)
	loginAttempts.Unlock()
	if enrolled != 0 {
		_, _ = s.S.DB.Exec(`INSERT INTO admin_state(id,failed_count,locked_until,last_totp_step) VALUES(1,0,'',?) ON CONFLICT(id) DO UPDATE SET failed_count=0,locked_until='',last_totp_step=excluded.last_totp_step`, step)
	}
	token := make([]byte, 32)
	if _, e = rand.Read(token); e != nil {
		adminErrOut(w, 500, "internal error")
		return
	}
	raw := base64.RawURLEncoding.EncodeToString(token)
	csrfB := make([]byte, 32)
	_, _ = rand.Read(csrfB)
	sess := adminSession{csrf: base64.RawURLEncoding.EncodeToString(csrfB), created: time.Now(), last: time.Now(), enrollOnly: enrolled == 0, mustChange: mustChange != 0}
	sessions.Lock()
	sessions.m[raw] = sess
	sessions.Unlock()
	s.audit("admin", "", "login", "", "", "ok", s.sourceIP(r))
	http.SetCookie(w, &http.Cookie{Name: "sws_admin", Value: raw, Path: "/admin", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: strings.HasPrefix(s.C.PublicBaseURL, "https://"), MaxAge: 28800})
	if sess.enrollOnly {
		if sess.mustChange {
			http.Redirect(w, r, "/admin/password", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/admin/totp/enroll", http.StatusSeeOther)
		}
		return
	}
	http.Redirect(w, r, "/admin/secrets", http.StatusSeeOther)
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
	// Re-check enrollment state so an out-of-band reset immediately downgrades existing sessions.
	var enrolled, mustChange int
	if err := s.S.DB.QueryRow(`SELECT totp_enrolled,must_change_password FROM admins WHERE id=1`).Scan(&enrolled, &mustChange); err == nil {
		if enrolled != 0 && v.enrollOnly {
			delete(sessions.m, ck.Value)
			http.SetCookie(w, &http.Cookie{Name: "sws_admin", Value: "", Path: "/admin", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return adminSession{}, false
		}
		if enrolled == 0 {
			v.enrollOnly = true
		}
		v.mustChange = mustChange != 0
	}
	sessions.m[ck.Value] = v
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		if subtle.ConstantTimeCompare([]byte(r.Form.Get("csrf")), []byte(v.csrf)) != 1 {
			adminErrOut(w, 403, "csrf rejected")
			return adminSession{}, false
		}
	}
	if v.enrollOnly {
		path := r.URL.Path
		allowed := path == "/admin/password" || path == "/admin/totp/enroll" || path == "/admin/logout"
		if !allowed {
			if v.mustChange {
				http.Redirect(w, r, "/admin/password", http.StatusSeeOther)
			} else {
				http.Redirect(w, r, "/admin/totp/enroll", http.StatusSeeOther)
			}
			return adminSession{}, false
		}
		if v.mustChange && path != "/admin/password" && path != "/admin/logout" {
			http.Redirect(w, r, "/admin/password", http.StatusSeeOther)
			return adminSession{}, false
		}
		if !v.mustChange && path != "/admin/totp/enroll" && path != "/admin/logout" {
			http.Redirect(w, r, "/admin/totp/enroll", http.StatusSeeOther)
			return adminSession{}, false
		}
	}
	return v, true
}
func (s *Server) adminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		adminErrOut(w, 405, "method not allowed")
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

var (
	panelViewportRE = regexp.MustCompile(`<meta name="viewport"[^>]*>`)
	panelStartRE    = regexp.MustCompile(`(?i)<(h1|form|p|section|div)\b`)
	panelTableRE    = regexp.MustCompile(`(?is)<table\b[^>]*>.*?</table>`)
	panelRowRE      = regexp.MustCompile(`(?is)<tr\b[^>]*>.*?</tr>`)
	panelTHRE       = regexp.MustCompile(`(?is)<th\b[^>]*>(.*?)</th>`)
	panelTDRE       = regexp.MustCompile(`(?i)<td\b([^>]*)>`)
	panelTagRE      = regexp.MustCompile(`(?is)<[^>]+>`)
)

func adminErrOut(w http.ResponseWriter, status int, msg string) {
	message := msg
	switch status {
	case http.StatusBadRequest:
		message = "请求无效，请检查输入后重试。"
	case http.StatusForbidden:
		message = "请求校验失败，请刷新页面后重试。"
	case http.StatusNotFound:
		message = "找不到这个页面。"
	case http.StatusMethodNotAllowed:
		message = "不支持的请求方法。"
	case http.StatusInternalServerError:
		message = "服务暂时无法完成请求，请稍后重试。"
	}
	renderStatus(w, status, `<!doctype html><html lang="zh"><meta charset="utf-8"><title>请求未完成</title><h1>请求未完成</h1><div class="note danger"><p>{{.Message}}</p>{{if .Detail}}<details><summary>技术详情</summary><p class="hint">{{.Detail}}</p></details>{{end}}</div><a href="/admin/">返回首页</a></html>`, map[string]string{"Message": message, "Detail": msg})
}

func render(w http.ResponseWriter, src string, data any) { renderStatus(w, http.StatusOK, src, data) }

func renderStatus(w http.ResponseWriter, status int, src string, data any) {
	if !strings.Contains(src, `name="viewport"`) {
		src = strings.Replace(src, `<meta charset="utf-8">`, `<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">`, 1)
	} else {
		src = panelViewportRE.ReplaceAllString(src, `<meta name="viewport" content="width=device-width,initial-scale=1">`)
	}
	src = strings.ReplaceAll(src, `<link rel="stylesheet" href="/admin/assets/admin.css">`, "")
	if !strings.Contains(src, `/admin/assets/admin.js`) {
		src = strings.Replace(src, `<meta charset="utf-8">`, `<meta charset="utf-8"><script src="/admin/assets/admin.js" defer></script>`, 1)
	}
	if !strings.Contains(src, `class="appbar"`) {
		if loc := panelStartRE.FindStringIndex(src); loc != nil {
			shell, footer := panelShell(src)
			src = src[:loc[0]] + shell + src[loc[0]:]
			if close := strings.LastIndex(strings.ToLower(src), `</html>`); close >= 0 {
				src = src[:close] + footer + src[close:]
			} else {
				src += footer + `</html>`
			}
		}
	}
	recorder := httptest.NewRecorder()
	panel.Render(recorder, src, data)
	body := addPanelTableLabels(recorder.Body.String())
	if recorder.Code >= http.StatusBadRequest {
		status = recorder.Code
	}
	if contentType := recorder.Header().Get("Content-Type"); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func addPanelTableLabels(document string) string {
	return panelTableRE.ReplaceAllStringFunc(document, func(table string) string {
		openEnd := strings.Index(table, ">")
		closeStart := strings.LastIndex(strings.ToLower(table), "</table>")
		if openEnd < 0 || closeStart < openEnd {
			return table
		}
		opening, inner := table[:openEnd+1], table[openEnd+1:closeStart]
		rows := panelRowRE.FindAllString(inner, -1)
		if len(rows) == 0 {
			return table
		}
		var labels []string
		headerIndex := -1
		for i, row := range rows {
			if strings.Contains(strings.ToLower(row), "<th") {
				headerIndex = i
				for _, match := range panelTHRE.FindAllStringSubmatch(row, -1) {
					labels = append(labels, strings.TrimSpace(stdhtml.UnescapeString(panelTagRE.ReplaceAllString(match[1], ""))))
				}
				break
			}
		}
		if headerIndex < 0 {
			return table
		}
		for i := range rows {
			if i == headerIndex || strings.Contains(strings.ToLower(rows[i]), "<th") {
				continue
			}
			cellIndex := 0
			rows[i] = panelTDRE.ReplaceAllStringFunc(rows[i], func(tag string) string {
				label := ""
				if cellIndex < len(labels) {
					label = labels[cellIndex]
				}
				cellIndex++
				if label == "" || strings.Contains(strings.ToLower(tag), "data-label=") {
					return tag
				}
				return strings.TrimSuffix(tag, ">") + ` data-label="` + template.HTMLEscapeString(label) + `">`
			})
		}
		var bodyRows []string
		for i, row := range rows {
			if i != headerIndex {
				bodyRows = append(bodyRows, row)
			}
		}
		return opening + `<thead>` + rows[headerIndex] + `</thead><tbody>` + strings.Join(bodyRows, "") + `</tbody></table>`
	})
}
