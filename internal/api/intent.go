package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	vaultcrypto "github.com/kyaring/sws-vault/internal/crypto"
	"github.com/kyaring/sws-vault/internal/provider"
	"net/http"
	"strings"
	"time"
)

func (s *Server) intent(w http.ResponseWriter, r *http.Request, c Client) {
	var q struct {
		Label string `json:"label"`
	}
	if decode(r, &q) != nil || strings.TrimSpace(q.Label) == "" {
		errOut(w, 400, "label required")
		return
	}
	raw, e := vaultcrypto.Random(32)
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	token := vaultcrypto.Encode(raw)
	wipe(raw)
	h := sha256.Sum256([]byte(token))
	exp := time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339)
	_, e = s.S.DB.Exec(`INSERT INTO intents(token_hash,ns,label,expires_at) VALUES(?,?,?,?)`, h[:], c.NS, q.Label, exp)
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	base := s.C.PublicBaseURL
	if base == "" {
		base = "http://127.0.0.1:9531"
	}
	s.audit(c.ID, c.NS, "intent", "", "", "ok", remoteIP(r))
	jsonOut(w, 201, map[string]string{"url": base + "/i/" + token, "expires_at": exp})
}
func (s *Server) intentPage(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	h := sha256.Sum256([]byte(token))
	var ns, label, exp, used string
	if e := s.S.DB.QueryRow(`SELECT ns,label,expires_at,used_at FROM intents WHERE token_hash=?`, h[:]).Scan(&ns, &label, &exp, &used); e != nil || used != "" || time.Now().UTC().Format(time.RFC3339) >= exp {
		errOut(w, 404, "intent expired or already used")
		return
	}
	csrf := make([]byte, 32)
	if _, e := rand.Read(csrf); e != nil {
		errOut(w, 500, "internal error")
		return
	}
	csrfText := base64.RawURLEncoding.EncodeToString(csrf)
	http.SetCookie(w, &http.Cookie{Name: "sv_intent_csrf", Value: csrfText, Path: "/i/" + token, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: strings.HasPrefix(s.C.PublicBaseURL, "https://"), MaxAge: 600})
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><title>安全录入</title><h1>安全录入：{{.Label}}</h1><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>平台 <select name="provider"><option>generic</option><option>cloudflare-token</option><option>cloudflare-global-key</option><option>github-pat</option><option>gitea-token</option></select></label><label>类型 <select name="type"><option>token</option><option>api_key</option><option>login</option><option>webhook</option><option>note</option></select></label><label>用户名（可选）<input name="username" autocomplete="off"></label><label>允许主机（逗号分隔）<input name="hosts" autocomplete="off"></label><label>值 <input type="password" name="value" autocomplete="off" required></label><button>保存一次</button></form></html>`, map[string]string{"Label": label, "CSRF": csrfText})
}
func (s *Server) intentSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errOut(w, 405, "method not allowed")
		return
	}
	token := r.PathValue("token")
	ck, e := r.Cookie("sv_intent_csrf")
	if e != nil {
		errOut(w, 403, "csrf rejected")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if e = r.ParseForm(); e != nil {
		errOut(w, 400, "invalid request")
		return
	}
	if subtle.ConstantTimeCompare([]byte(ck.Value), []byte(r.Form.Get("csrf"))) != 1 {
		errOut(w, 403, "csrf rejected")
		return
	}
	h := sha256.Sum256([]byte(token))
	var ns, label, exp, used string
	if e = s.S.DB.QueryRow(`SELECT ns,label,expires_at,used_at FROM intents WHERE token_hash=?`, h[:]).Scan(&ns, &label, &exp, &used); e != nil || used != "" || time.Now().UTC().Format(time.RFC3339) >= exp {
		errOut(w, 404, "intent expired or already used")
		return
	}
	value := r.Form.Get("value")
	if value == "" || len(value) > 1<<20 {
		errOut(w, 400, "invalid value")
		return
	}
	hosts := []string{}
	for _, v := range strings.Split(r.Form.Get("hosts"), ",") {
		if v = strings.TrimSpace(v); v != "" {
			hosts = append(hosts, v)
		}
	}
	prov := r.Form.Get("provider")
	bindings := Binding{Hosts: hosts}
	if len(hosts) == 0 {
		bindings.Hosts = provider.DefaultHosts(prov)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, e := s.S.DB.Exec(`UPDATE intents SET used_at=? WHERE token_hash=? AND used_at='' AND expires_at>?`, now, h[:], now)
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		errOut(w, 404, "intent expired or already used")
		return
	}
	m, e := s.save(SecretRequest{NS: ns, Label: label, Provider: prov, Type: r.Form.Get("type"), Username: r.Form.Get("username"), Value: value, Bindings: bindings}, false, "")
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	s.audit("intent", ns, "write", m.ID, "", "ok", remoteIP(r))
	w.Header().Set("Cache-Control", "no-store")
	render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><title>录入完成</title><p>录入成功。凭据值不会再次显示。</p></html>`, nil)
}
