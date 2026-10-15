package api

import (
	"crypto/rand"
	"crypto/subtle"
	"html/template"
	"net/http"
	"time"

	"github.com/kyaring/sws-vault/internal/auth"
)

func (s *Server) adminChangePassword(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	if !sess.enrollOnly || !sess.mustChange {
		http.Redirect(w, r, "/admin/totp/enroll", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		w.Header().Set("Cache-Control", "no-store")
		render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>修改初始密码</title><h1>修改初始密码</h1><p class="lead">首次设置 1/2</p><ol class="steps"><li>修改初始密码</li><li>设置双重验证</li></ol><p class="note">新密码至少 12 个字符，且不能与当前密码相同。</p><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>当前密码 <input type="password" name="current" autocomplete="current-password" required></label><label>新密码 <input type="password" name="password" autocomplete="new-password" minlength="12" required></label><div class="bar"><button class="btn block">修改密码</button></div></form>`, map[string]string{"CSRF": sess.csrf})
		return
	}
	if r.Method != http.MethodPost {
		adminErrOut(w, 405, "method not allowed")
		return
	}
	_ = r.ParseForm()
	current, next := r.Form.Get("current"), r.Form.Get("password")
	var hash, salt []byte
	if e := s.S.DB.QueryRow(`SELECT password_hash,password_salt FROM admins WHERE id=1`).Scan(&hash, &salt); e != nil {
		adminErrOut(w, 500, "internal error")
		return
	}
	got, e := auth.HashPassword(current, salt)
	if e != nil || subtle.ConstantTimeCompare(got, hash) != 1 || len(next) < 12 || next == current {
		s.audit("admin", "", "password-changed", "", "", "failed", s.sourceIP(r))
		adminErrOut(w, 400, "invalid password change")
		return
	}
	newSalt := make([]byte, 16)
	if _, e = rand.Read(newSalt); e != nil {
		adminErrOut(w, 500, "internal error")
		return
	}
	newHash, e := auth.HashPassword(next, newSalt)
	if e != nil {
		adminErrOut(w, 500, "internal error")
		return
	}
	if _, e = s.S.DB.Exec(`UPDATE admins SET password_hash=?,password_salt=?,must_change_password=0 WHERE id=1`, newHash, newSalt); e != nil {
		adminErrOut(w, 500, "internal error")
		return
	}
	if ck, e := r.Cookie("sws_admin"); e == nil {
		sessions.Lock()
		v := sessions.m[ck.Value]
		v.mustChange = false
		sessions.m[ck.Value] = v
		sessions.Unlock()
	}
	s.audit("admin", "", "password-changed", "", "", "ok", s.sourceIP(r))
	http.Redirect(w, r, "/admin/totp/enroll", http.StatusSeeOther)
}

func (s *Server) adminEnrollTOTP(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	if !sess.enrollOnly {
		render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><h1>双重验证已启用</h1><p>验证器密钥不会再次显示。</p><a href="/admin/">返回面板</a>`, nil)
		return
	}
	var enrolled int
	if e := s.S.DB.QueryRow(`SELECT totp_enrolled FROM admins WHERE id=1`).Scan(&enrolled); e != nil {
		adminErrOut(w, 500, "internal error")
		return
	}
	if enrolled != 0 {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		if s.loginLocked(s.sourceIP(r)) {
			adminErrOut(w, 429, "login temporarily locked")
			return
		}
		_ = r.ParseForm()
		var secret []byte
		var expires string
		e := s.S.DB.QueryRow(`SELECT pending_totp_secret,pending_totp_expires FROM admins WHERE id=1`).Scan(&secret, &expires)
		deadline, parseErr := time.Parse(time.RFC3339, expires)
		if e != nil || len(secret) == 0 || parseErr != nil || !time.Now().Before(deadline) {
			_, _ = s.S.DB.Exec(`UPDATE admins SET pending_totp_secret=NULL,pending_totp_expires='' WHERE id=1`)
			s.loginFailure(s.sourceIP(r))
			adminErrOut(w, 401, "enrollment expired; reload this page")
			return
		}
		step, valid := auth.VerifyTOTP(secret, r.Form.Get("code"), time.Now(), -1)
		if !valid {
			s.loginFailure(s.sourceIP(r))
			s.audit("admin", "", "totp-enrolled", "", "", "failed", s.sourceIP(r))
			adminErrOut(w, 401, "invalid verification code")
			return
		}
		if _, e = s.S.DB.Exec(`UPDATE admins SET totp_secret=pending_totp_secret,totp_enrolled=1,pending_totp_secret=NULL,pending_totp_expires='',must_change_password=0 WHERE id=1`); e != nil {
			adminErrOut(w, 500, "internal error")
			return
		}
		_, _ = s.S.DB.Exec(`INSERT INTO admin_state(id,failed_count,locked_until,last_totp_step) VALUES(1,0,'',?) ON CONFLICT(id) DO UPDATE SET failed_count=0,locked_until='',last_totp_step=excluded.last_totp_step`, step)
		// Invalidate every restricted enrollment session; none may be promoted after TOTP is enabled.
		sessions.Lock()
		for token, session := range sessions.m {
			if session.enrollOnly {
				delete(sessions.m, token)
			}
		}
		sessions.Unlock()
		if _, e := r.Cookie("sws_admin"); e == nil {
			http.SetCookie(w, &http.Cookie{Name: "sws_admin", Value: "", Path: "/admin", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		}
		loginAttempts.Lock()
		delete(loginAttempts.m, s.sourceIP(r))
		loginAttempts.Unlock()
		s.audit("admin", "", "totp-enrolled", "", "", "ok", s.sourceIP(r))
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodGet {
		adminErrOut(w, 405, "method not allowed")
		return
	}
	secret, encoded, e := auth.NewTOTPSecret()
	if e != nil {
		adminErrOut(w, 500, "internal error")
		return
	}
	expires := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)
	if _, e = s.S.DB.Exec(`UPDATE admins SET pending_totp_secret=?,pending_totp_expires=? WHERE id=1 AND totp_enrolled=0`, secret, expires); e != nil {
		adminErrOut(w, 500, "internal error")
		return
	}
	uri := "otpauth://totp/admin?secret=" + encoded + "&issuer=SWSVault"
	qr, qrErr := qrSVG(uri)
	for i := range secret {
		secret[i] = 0
	}
	w.Header().Set("Cache-Control", "no-store")
	s.renderTOTPEnrollmentPage(w, sess.csrf, encoded, qr, qrErr != nil)
}

func (s *Server) renderTOTPEnrollmentPage(w http.ResponseWriter, csrf, encoded, qr string, qrFailed bool) {
	render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>设置双重验证</title><h1>设置双重验证</h1><p class="lead">首次设置 2/2</p><ol class="steps"><li>修改初始密码</li><li>设置双重验证</li></ol><p class="note warn">本次密钥有效期为 10 分钟，刷新页面会生成新密钥。</p>{{if .QRFailed}}<p>二维码生成失败，请在验证器中手动输入下方密钥。</p>{{else}}<p>请使用验证器扫描二维码，然后输入当前 6 位验证码。</p><div class="qr">{{.QR}}</div>{{end}}<details><summary>无法扫码？查看手动密钥</summary><p>请在验证器中手动输入密钥：</p><p><code>{{.Secret}}</code></p></details><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>6 位验证码 <input name="code" inputmode="numeric" pattern="[0-9]{6}" minlength="6" maxlength="6" required></label><div class="bar"><button class="btn block">确认并启用</button></div></form>`, map[string]any{"QR": template.HTML(qr), "QRFailed": qrFailed, "Secret": encoded, "CSRF": csrf})
}
