package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// 接入方详情 /admin/projects/{name}/clients/{id}（SV-20261016-07 G，设计稿 ⑥）：
// 展示名称、备注、创建时间、权限、来源 IP、状态与最近使用；「能用哪些密钥」与 D 的「谁在用」
// 写的是同一份 AllowedClients 数据；可改备注 / 权限 / 来源 IP，可重新生成通行证或停用。
// URL 里的项目与接入方所属不符一律 404。

func (s *Server) loadProjectClient(name, clientID string) (Client, bool) {
	var c Client
	if !namePattern.MatchString(clientID) {
		return c, false
	}
	if e := s.S.DB.QueryRow(`SELECT id,ns,name,scopes,cidrs,expires_at,disabled FROM clients WHERE id=?`, clientID).Scan(&c.ID, &c.NS, &c.Name, &c.Scopes, &c.CIDRs, &c.Expires, &c.Disabled); e != nil || c.NS != name {
		return Client{}, false
	}
	return c, true
}

// clientLastUsed 取接入方最近一次代发 / 取明文的时间。
func (s *Server) clientLastUsed(clientID string) string {
	var at string
	if e := s.S.DB.QueryRow(`SELECT at FROM audit WHERE actor=? AND action IN ('fetch','resolve') ORDER BY id DESC LIMIT 1`, clientID).Scan(&at); e != nil {
		return "从未使用"
	}
	return relativeUseTime(at)
}

// clientPermissionChoice 把 scopes 归一成面板上的两种权限；不是这两种之一的旧接入方返回 ""。
func clientPermissionChoice(scopes string) string {
	canonicalFetch := "secrets:list,fetch"
	canonicalResolve := "secrets:list,resolve,fetch"
	switch strings.TrimSpace(scopes) {
	case canonicalFetch:
		return "fetch"
	case canonicalResolve:
		return "resolve"
	}
	return ""
}

func (s *Server) adminProjectClientDetail(w http.ResponseWriter, r *http.Request, name, clientID string) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	c, ok := s.loadProjectClient(name, clientID)
	if !ok {
		adminErrOut(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method == http.MethodPost {
		s.adminProjectClientUpdate(w, r, name, c)
		return
	}
	if r.Method != http.MethodGet {
		adminErrOut(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var note, created string
	if e := s.S.DB.QueryRow(`SELECT note,created_at FROM clients WHERE id=?`, clientID).Scan(&note, &created); e != nil {
		adminErrOut(w, http.StatusNotFound, "not found")
		return
	}
	// 能用哪些密钥：本项目全部密钥，勾选状态与 D 的「谁在用」是同一份数据。
	type secretView struct {
		ID, Label, Provider, Tail string
		Allowed                   bool
	}
	var secrets []secretView
	rows, e := s.S.DB.Query(`SELECT id,label,provider,preview,bindings FROM secrets WHERE ns=? AND status='active' ORDER BY label`, name)
	if e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	for rows.Next() {
		var id, label, provider, preview, raw string
		if rows.Scan(&id, &label, &provider, &preview, &raw) != nil {
			continue
		}
		var bd Binding
		_ = json.Unmarshal([]byte(raw), &bd)
		allowed := false
		switch {
		case bd.NoClientAccess:
			allowed = false
		case len(bd.AllowedClients) > 0:
			allowed = containsID(bd.AllowedClients, clientID)
		default:
			allowed = c.Disabled == 0
		}
		secrets = append(secrets, secretView{ID: id, Label: label, Provider: providerLabel(provider), Tail: secretTail(preview), Allowed: allowed})
	}
	rows.Close()
	if e := rows.Err(); e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	choice := clientPermissionChoice(c.Scopes)
	page := `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>接入方详情</title><h1>{{.Name}}</h1><p class="lead">{{if .Note}}{{.Note}} · {{end}}创建于 {{.Created}}</p><div class="group"><span class="row"><span class="t">状态<small>{{if .Disabled}}<span class="badge">已停用</span>{{else}}<span class="badge ok">正常</span>{{end}} · 最近使用 {{.LastUsed}}</small></span></span></div><h2>设置</h2><form method="post" action="/admin/projects/` + name + `/clients/` + clientID + `"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>备注 <input name="note" maxlength="100" value="{{.Note}}" autocomplete="off"></label>`
	if choice == "" {
		page += `<div class="group"><span class="row"><span class="t">权限<small>自定义 · {{.Scopes}}</small></span></span></div><p class="hint">这个接入方的权限不是「仅代发 / 可取明文」两种之一，面板只读展示；需要改权限请重建一个接入方。</p>`
	} else {
		page += `<label>权限 <select name="permission"><option value="fetch"{{if eq .Choice "fetch"}} selected{{end}}>仅代发（推荐）</option><option value="resolve"{{if eq .Choice "resolve"}} selected{{end}}>可取明文</option></select><small class="hint">仅代发：接入方拿不到密钥值，只能让 Vault 帮它发请求。可取明文：它能直接读到密钥值，只给受信任的程序用。</small></label>`
	}
	page += `<label>来源 IP（可选） <input name="cidrs" value="{{.CIDRs}}" autocomplete="off" placeholder="留空即不限，例如 10.0.0.0/8"><small class="hint">留空表示不限来源；单个 IP 会自动补成 /32 或 /128。</small></label><button class="btn block">保存</button></form><h2>能用哪些密钥</h2>`
	if len(secrets) == 0 {
		page += `<p class="hint">这个项目还没有密钥。</p>`
	} else {
		page += `<form method="post" action="/admin/projects/` + name + `/clients/` + clientID + `/secrets"><input type="hidden" name="csrf" value="{{.CSRF}}"><div class="group">{{range .Secrets}}<label class="check"><input type="checkbox" name="secret" value="{{.ID}}"{{if .Allowed}} checked{{end}}><span class="t">{{.Label}}<small>{{.Provider}} · 尾号 {{.Tail}}</small></span></label>{{end}}</div><button class="btn block">保存</button></form>`
	}
	if c.Disabled == 0 {
		page += `<div class="bar-actions"><form method="post" action="/admin/projects/` + name + `/clients/` + clientID + `/regenerate"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="btn secondary block">重新生成通行证</button></form></div><form method="post" action="/admin/clients/` + clientID + `/disable"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="btn danger block">停用</button></form>`
	}
	page += `</html>`
	render(w, page, map[string]any{"CSRF": sess.csrf, "Name": c.Name, "Note": note, "Created": relativeUseTime(created), "Disabled": c.Disabled != 0, "LastUsed": s.clientLastUsed(clientID), "Choice": choice, "Scopes": c.Scopes, "CIDRs": c.CIDRs, "Secrets": secrets})
}

// adminProjectClientUpdate 保存备注 / 权限 / 来源 IP（G）。
func (s *Server) adminProjectClientUpdate(w http.ResponseWriter, r *http.Request, name string, c Client) {
	_ = r.ParseForm()
	note := strings.TrimSpace(r.Form.Get("note"))
	if runeLen(note) > clientNoteMaxRunes {
		adminErrOut(w, http.StatusBadRequest, fmt.Sprintf("备注最多 %d 字", clientNoteMaxRunes))
		return
	}
	cidrs, cidrErr := normalizeCIDRs(r.Form.Get("cidrs"))
	if cidrErr != nil {
		adminErrOut(w, http.StatusBadRequest, "限制来源 IP 无效：请填写 IP 或 CIDR，多个用英文逗号分隔，例如 10.0.0.0/8, 192.168.1.5")
		return
	}
	choice := clientPermissionChoice(c.Scopes)
	scopes := c.Scopes
	// 只有规范权限才允许切换；「自定义」保持只读（G）。
	if choice != "" {
		if want := strings.TrimSpace(r.Form.Get("permission")); want == "fetch" || want == "resolve" {
			if want == "resolve" {
				scopes = "secrets:list,resolve,fetch"
			} else {
				scopes = "secrets:list,fetch"
			}
		}
	}
	tx, e := s.S.DB.Begin()
	if e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`UPDATE clients SET note=?,cidrs=?,scopes=? WHERE id=?`, note, strings.Join(cidrs, ","), scopes, c.ID); e != nil {
		adminErrOut(w, http.StatusInternalServerError, "could not update client")
		return
	}
	// 改成「可取明文」时，对它已授权的密钥打开 AllowResolve；未授权给它的密钥不动（G）。
	if hasScope(scopes, "resolve") && !hasScope(c.Scopes, "resolve") {
		rows, e := tx.Query(`SELECT id,bindings FROM secrets WHERE ns=? AND status='active'`, name)
		if e != nil {
			adminErrOut(w, http.StatusInternalServerError, "internal error")
			return
		}
		type secretRow struct{ id, bindings string }
		var list []secretRow
		for rows.Next() {
			var v secretRow
			if rows.Scan(&v.id, &v.bindings) != nil {
				rows.Close()
				adminErrOut(w, http.StatusInternalServerError, "internal error")
				return
			}
			list = append(list, v)
		}
		rows.Close()
		if e := rows.Err(); e != nil {
			adminErrOut(w, http.StatusInternalServerError, "internal error")
			return
		}
		for _, v := range list {
			bd, e := decodeBinding(v.bindings)
			if e != nil {
				adminErrOut(w, http.StatusInternalServerError, "invalid stored policy")
				return
			}
			authorized := (len(bd.AllowedClients) > 0 && containsID(bd.AllowedClients, c.ID)) || (len(bd.AllowedClients) == 0 && !bd.NoClientAccess)
			if !authorized || bd.AllowResolve {
				continue
			}
			bd.AllowResolve = true
			if e := saveBinding(tx, v.id, bd); e != nil {
				adminErrOut(w, http.StatusInternalServerError, "could not update grants")
				return
			}
		}
	}
	if e := tx.Commit(); e != nil {
		adminErrOut(w, http.StatusInternalServerError, "could not commit client")
		return
	}
	s.audit("admin", name, "client-update", c.ID, "", "ok", s.sourceIP(r))
	http.Redirect(w, r, "/admin/projects/"+name+"/clients/"+c.ID, http.StatusSeeOther)
}

// adminProjectClientRegenerate 重新生成通行证：旧令牌立即失效，新令牌只显示一次（G，复用 SV-04 结果页）。
func (s *Server) adminProjectClientRegenerate(w http.ResponseWriter, r *http.Request, name, clientID string) {
	if _, ok := s.adminSession(w, r); !ok {
		return
	}
	if r.Method != http.MethodPost {
		adminErrOut(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	c, ok := s.loadProjectClient(name, clientID)
	if !ok {
		adminErrOut(w, http.StatusNotFound, "not found")
		return
	}
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	token := "swsv_" + base64.RawURLEncoding.EncodeToString(raw)
	for i := range raw {
		raw[i] = 0
	}
	sum := sha256.Sum256([]byte(token))
	if _, e := s.S.DB.Exec(`UPDATE clients SET token_hash=? WHERE id=?`, sum[:], clientID); e != nil {
		adminErrOut(w, http.StatusInternalServerError, "could not regenerate token")
		return
	}
	count := 0
	rows, e := s.S.DB.Query(`SELECT bindings FROM secrets WHERE ns=? AND status='active'`, name)
	if e == nil {
		for rows.Next() {
			var rawB string
			if rows.Scan(&rawB) != nil {
				continue
			}
			var bd Binding
			if json.Unmarshal([]byte(rawB), &bd) != nil {
				continue
			}
			if (len(bd.AllowedClients) > 0 && containsID(bd.AllowedClients, clientID)) || (len(bd.AllowedClients) == 0 && !bd.NoClientAccess) {
				count++
			}
		}
		rows.Close()
	}
	s.audit("admin", name, "client-regenerate", clientID, "", "ok", s.sourceIP(r))
	s.renderPassport(w, passportView{
		Project:      name,
		Title:        "通行证已重新生成",
		Token:        token,
		AllowResolve: hasScope(c.Scopes, "resolve"),
		CIDRs:        c.CIDRs,
		Count:        count,
		ScopeNote:    "旧通行证已立即失效；新通行证只显示这一次。已授权的密钥不变。",
		BackHref:     "/admin/projects/" + name + "/clients/" + clientID,
		BackLabel:    "返回接入方",
	})
}
