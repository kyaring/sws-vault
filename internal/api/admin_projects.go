package api

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	vaultcrypto "github.com/kyaring/sws-vault/internal/crypto"
)

const (
	projectDescriptionMaxRunes = 200
	clientNoteMaxRunes         = 100
)

func runeLen(v string) int { return len([]rune(v)) }

func truncateRunes(v string, n int) string {
	r := []rune(v)
	if len(r) <= n {
		return v
	}
	return string(r[:n]) + "…"
}

var providerLabels = map[string]string{
	"cloudflare-token":      "Cloudflare",
	"cloudflare-global-key": "Cloudflare 全局密钥",
	"github-pat":            "GitHub",
	"gitea-token":           "Gitea",
	"generic":               "通用",
}

func providerLabel(name string) string {
	if v, ok := providerLabels[name]; ok {
		return v
	}
	return name
}

// clientPermission 把 scopes 翻译成面板文案：只有带 resolve 的才叫「可取明文」。
func clientPermission(scopes string) string {
	if hasScope(scopes, "resolve") {
		return "可取明文"
	}
	return "仅代发"
}

func clientSourceIP(cidrs string) string {
	if strings.TrimSpace(cidrs) == "" {
		return "不限"
	}
	return cidrs
}

func projectSecretsURL(name string) string { return "/admin/projects/" + name + "/secrets/import" }

// adminProjects 是项目列表页。
func (s *Server) adminProjects(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminSession(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		adminErrOut(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	rows, e := s.S.DB.Query(`SELECT n.name,n.description,(SELECT count(*) FROM secrets x WHERE x.ns=n.name AND x.status='active'),(SELECT count(*) FROM clients c WHERE c.ns=n.name AND c.disabled=0) FROM namespaces n WHERE n.name<>? AND substr(n.name,1,1)<>'_' ORDER BY n.name`, unassignedNS)
	if e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()
	type item struct {
		Name, Description string
		Secrets, Clients  int
	}
	var list []item
	for rows.Next() {
		var v item
		if rows.Scan(&v.Name, &v.Description, &v.Secrets, &v.Clients) == nil {
			v.Description = truncateRunes(v.Description, 48)
			list = append(list, v)
		}
	}
	render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>项目</title><h1>项目</h1><p class="lead">一个项目放一组密钥，再给每个使用方发一张通行证。</p>{{if .Items}}<div class="group">{{range .Items}}<a class="row" href="/admin/projects/{{.Name}}"><span class="dot" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M3 7 12 3l9 4-9 4zM3 7v10l9 4 9-4V7M12 11v10" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/></svg></span><span class="t">{{.Name}}<small>{{if .Description}}{{.Description}}{{else}}还没有简介{{end}}</small></span><span class="v">{{.Secrets}} 密钥 · {{.Clients}} 接入方</span></a>{{end}}</div>{{else}}<p class="hint">还没有项目。选择下面的「新建项目」开始。</p>{{end}}<div class="bar"><a class="btn block" href="/admin/projects/new">新建项目</a></div>`, map[string]any{"Items": list})
}

// adminProjectNew 处理新建项目。
func (s *Server) adminProjectNew(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>新建项目</title><h1>新建项目</h1><p class="lead">先给项目起个名字，写一段简介说明这里面的密钥是干什么的。</p><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>项目名 <input name="name" pattern="[A-Za-z0-9._-]{1,64}" autocomplete="off" required><small class="hint">字母、数字、点、下划线、连字符。</small></label><label>简介 <textarea name="description" rows="3" maxlength="200"></textarea><small class="hint">最多 200 字，之后随时可以改。简介只是说明文字，不要写密钥值。</small></label><div class="bar"><button class="btn block">创建项目</button></div></form>`, map[string]any{"CSRF": sess.csrf})
		return
	}
	if r.Method != http.MethodPost {
		adminErrOut(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.Form.Get("name"))
	description := strings.TrimSpace(r.Form.Get("description"))
	if strings.HasPrefix(name, "_") {
		adminErrOut(w, http.StatusBadRequest, "这是系统保留名称")
		return
	}
	if !namePattern.MatchString(name) {
		adminErrOut(w, http.StatusBadRequest, "项目名只能用字母、数字、点、下划线、连字符，最多 64 位")
		return
	}
	if runeLen(description) > projectDescriptionMaxRunes {
		adminErrOut(w, http.StatusBadRequest, fmt.Sprintf("简介最多 %d 字", projectDescriptionMaxRunes))
		return
	}
	id, e := randomID()
	if e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	res, e := s.S.DB.Exec(`INSERT INTO namespaces(id,name,description,created_at) VALUES(?,?,?,?) ON CONFLICT(name) DO NOTHING`, id, name, description, time.Now().UTC().Format(time.RFC3339))
	if e != nil {
		adminErrOut(w, http.StatusBadRequest, "项目名已存在")
		return
	}
	if n, _ := res.RowsAffected(); n != 1 {
		adminErrOut(w, http.StatusBadRequest, "项目名已存在")
		return
	}
	s.audit("admin", name, "project-create", "", "", "ok", s.sourceIP(r))
	http.Redirect(w, r, "/admin/projects/"+name, http.StatusSeeOther)
}

// adminProjectRoute 分发 /admin/projects/{name} 下的子路由。
func (s *Server) adminProjectRoute(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/admin/projects/")
	parts := strings.Split(rest, "/")
	name := parts[0]
	if !namePattern.MatchString(name) || strings.HasPrefix(name, "_") {
		adminErrOut(w, http.StatusNotFound, "not found")
		return
	}
	suffix := strings.Join(parts[1:], "/")
	switch suffix {
	case "":
		s.adminProjectDetail(w, r, name)
	case "description":
		s.adminProjectDescription(w, r, name)
	case "clients/new":
		s.adminProjectClientNew(w, r, name)
	case "secrets/import":
		s.adminProjectSecretsImport(w, r, name)
	default:
		adminErrOut(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) projectExists(name string) bool {
	var n int
	return s.S.DB.QueryRow(`SELECT count(*) FROM namespaces WHERE name=? AND substr(name,1,1)<>'_'`, name).Scan(&n) == nil && n == 1
}

// adminProjectDetail 渲染项目详情：简介、密钥、接入方。
func (s *Server) adminProjectDetail(w http.ResponseWriter, r *http.Request, name string) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		adminErrOut(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var description string
	if e := s.S.DB.QueryRow(`SELECT description FROM namespaces WHERE name=?`, name).Scan(&description); e != nil {
		adminErrOut(w, http.StatusNotFound, "not found")
		return
	}
	type secretRow struct{ ID, Label, Provider, Status, LastUsed string }
	var secrets []secretRow
	rows, e := s.S.DB.Query(`SELECT id,label,provider,status,last_used_at FROM secrets WHERE ns=? ORDER BY created_at DESC`, name)
	if e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	for rows.Next() {
		var v secretRow
		if rows.Scan(&v.ID, &v.Label, &v.Provider, &v.Status, &v.LastUsed) == nil {
			v.Provider = providerLabel(v.Provider)
			if v.Status == "active" {
				v.Status = "有效"
			} else {
				v.Status = "已停用"
			}
			if v.LastUsed == "" {
				v.LastUsed = "从未使用"
			} else {
				v.LastUsed = relativeUseTime(v.LastUsed)
			}
			secrets = append(secrets, v)
		}
	}
	rows.Close()
	type clientRow struct{ ID, Name, Note, Permission, SourceIP, Status, Created string }
	var clients []clientRow
	crows, e := s.S.DB.Query(`SELECT id,name,note,scopes,cidrs,disabled,created_at FROM clients WHERE ns=? ORDER BY created_at DESC`, name)
	if e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	for crows.Next() {
		var v clientRow
		var scopes, cidrs string
		var disabled int
		if crows.Scan(&v.ID, &v.Name, &v.Note, &scopes, &cidrs, &disabled, &v.Created) == nil {
			v.Permission = clientPermission(scopes)
			v.SourceIP = clientSourceIP(cidrs)
			if disabled != 0 {
				v.Status = "已停用"
			} else {
				v.Status = "正常"
			}
			v.Created = relativeUseTime(v.Created)
			clients = append(clients, v)
		}
	}
	crows.Close()
	var unassignedCount int
	_ = s.S.DB.QueryRow(`SELECT count(*) FROM secrets WHERE ns=? AND status='active'`, unassignedNS).Scan(&unassignedCount)
	render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>项目详情</title><h1>{{.Name}}</h1><p class="lead">{{if .Description}}{{.Description}}{{else}}还没有简介。{{end}}</p><form method="post" action="/admin/projects/{{.Name}}/description"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>简介 <textarea name="description" rows="3" maxlength="200">{{.Description}}</textarea><small class="hint">最多 200 字。这里只写说明，不要写密钥值。</small></label><button class="btn secondary">保存简介</button></form><h2>密钥</h2>{{if .Secrets}}<div class="group">{{range .Secrets}}<div class="row"><span class="dot" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="8" cy="15" r="4" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="m11 12 8-8 2 2-2 2 2 2-3 3-2-2-3 3" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg></span><span class="t">{{.Label}}<small>{{.Provider}} · {{.Status}} · {{.LastUsed}}</small></span><a href="/admin/secrets/{{.ID}}/bindings">使用范围</a></div>{{end}}</div>{{else}}<p class="hint">这个项目还没有密钥。</p>{{end}}<div class="group"><a class="row" href="/admin/secrets/new?project={{.Name}}&from=project"><span class="dot" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></span><span class="t">新建密钥<small>新建后直接属于本项目</small></span></a><a class="row" href="{{.ImportURL}}"><span class="dot" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 19V5M5 12l7-7 7 7" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg></span><span class="t">从未关联移入<small>未关联区现有 {{.Unassigned}} 个密钥</small></span></a></div><h2>接入方</h2>{{if .Clients}}<div class="group">{{range .Clients}}<div class="row"><span class="dot" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="9" cy="8" r="3" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="M3 20v-2a6 6 0 0 1 12 0v2M17 5a3 3 0 0 1 0 6" fill="none" stroke="currentColor" stroke-width="1.7"/></svg></span><span class="t">{{.Name}}<small>{{if .Note}}{{.Note}} · {{end}}{{.Permission}} · 来源 IP {{.SourceIP}} · {{.Status}} · {{.Created}}</small></span><form method="post" action="/admin/clients/{{.ID}}/disable" class="inline-form"><input type="hidden" name="csrf" value="{{$.CSRF}}"><button class="btn small danger">停用</button></form></div>{{end}}</div>{{else}}<p class="hint">还没有接入方。选择下面的「添加接入方」给使用方发一张通行证。</p>{{end}}<div class="bar"><a class="btn block" href="/admin/projects/{{.Name}}/clients/new">添加接入方</a></div>`, map[string]any{"CSRF": sess.csrf, "Name": name, "Description": description, "Secrets": secrets, "Clients": clients, "Unassigned": unassignedCount, "ImportURL": projectSecretsURL(name)})
}

// adminProjectDescription 保存项目简介。
func (s *Server) adminProjectDescription(w http.ResponseWriter, r *http.Request, name string) {
	if _, ok := s.adminSession(w, r); !ok {
		return
	}
	if r.Method != http.MethodPost {
		adminErrOut(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	_ = r.ParseForm()
	description := strings.TrimSpace(r.Form.Get("description"))
	if runeLen(description) > projectDescriptionMaxRunes {
		adminErrOut(w, http.StatusBadRequest, fmt.Sprintf("简介最多 %d 字", projectDescriptionMaxRunes))
		return
	}
	res, e := s.S.DB.Exec(`UPDATE namespaces SET description=? WHERE name=?`, description, name)
	if e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	if n, _ := res.RowsAffected(); n != 1 {
		adminErrOut(w, http.StatusNotFound, "not found")
		return
	}
	s.audit("admin", name, "project-description", "", "", "ok", s.sourceIP(r))
	http.Redirect(w, r, "/admin/projects/"+name, http.StatusSeeOther)
}

// adminProjectSecretsImport 把「未关联」的密钥移入本项目。
func (s *Server) adminProjectSecretsImport(w http.ResponseWriter, r *http.Request, name string) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	if !s.projectExists(name) {
		adminErrOut(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method == http.MethodGet {
		type item struct{ ID, Label, Provider, Hosts string }
		var list []item
		rows, e := s.S.DB.Query(`SELECT id,label,provider,bindings FROM secrets WHERE ns=? AND status='active' ORDER BY label`, unassignedNS)
		if e != nil {
			adminErrOut(w, http.StatusInternalServerError, "internal error")
			return
		}
		for rows.Next() {
			var v item
			var raw string
			if rows.Scan(&v.ID, &v.Label, &v.Provider, &raw) == nil {
				var bd Binding
				_ = json.Unmarshal([]byte(raw), &bd)
				v.Provider = providerLabel(v.Provider)
				v.Hosts = strings.Join(bd.Hosts, ", ")
				list = append(list, v)
			}
		}
		rows.Close()
		render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>从未关联移入</title><h1>从未关联移入</h1><p class="lead">移入 {{.Name}} 的密钥默认不授权给任何接入方，也不允许取明文；之后在「添加接入方」里勾选才会放行。</p>{{if .Items}}<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><div class="group">{{range .Items}}<label class="check"><input type="checkbox" name="secret" value="{{.ID}}"><span class="t">{{.Label}}<small>{{.Provider}}{{if .Hosts}} · {{.Hosts}}{{end}}</small></span></label>{{end}}</div><div class="bar"><button class="btn block">移入本项目</button></div></form>{{else}}<p class="hint">未关联区没有可移入的密钥。</p>{{end}}`, map[string]any{"CSRF": sess.csrf, "Name": name, "Items": list})
		return
	}
	if r.Method != http.MethodPost {
		adminErrOut(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	_ = r.ParseForm()
	selected := r.Form["secret"]
	if len(selected) == 0 {
		adminErrOut(w, http.StatusBadRequest, "请至少选择一个密钥")
		return
	}
	tx, e := s.S.DB.Begin()
	if e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback()
	moved := 0
	for _, sid := range selected {
		var oldNS, typ string
		var version int
		var ct, wrapped []byte
		var b string
		e = tx.QueryRow(`SELECT ns,type,key_version,ciphertext,dek_wrapped,bindings FROM secrets WHERE id=? AND status='active'`, sid).Scan(&oldNS, &typ, &version, &ct, &wrapped, &b)
		if e != nil || oldNS != unassignedNS {
			adminErrOut(w, http.StatusBadRequest, "selected secret unavailable")
			return
		}
		var bd Binding
		if json.Unmarshal([]byte(b), &bd) != nil {
			adminErrOut(w, http.StatusInternalServerError, "invalid stored policy")
			return
		}
		dek, e := s.unwrapDEK(oldNS, sid, uint32(version), wrapped)
		if e != nil {
			adminErrOut(w, http.StatusInternalServerError, "could not move selected secret")
			return
		}
		value, e := vaultcrypto.Open(dek, ct, vaultcrypto.SecretAAD(oldNS, sid, typ, uint32(version)))
		if e != nil {
			wipe(dek)
			adminErrOut(w, http.StatusInternalServerError, "could not move selected secret")
			return
		}
		newCT, e := vaultcrypto.Seal(dek, value, vaultcrypto.SecretAAD(name, sid, typ, uint32(version)))
		if e != nil {
			wipe(dek)
			wipe(value)
			adminErrOut(w, http.StatusInternalServerError, "could not move selected secret")
			return
		}
		newWrapped, e := s.wrapDEK(name, sid, uint32(version), dek)
		wipe(dek)
		wipe(value)
		if e != nil {
			adminErrOut(w, http.StatusInternalServerError, "could not move selected secret")
			return
		}
		// 移入后不授权给任何接入方，也不允许取明文。
		bd.AllowResolve = false
		bd.AllowedClients = nil
		bd.NoClientAccess = true
		bb, _ := json.Marshal(bd)
		if _, e = tx.Exec(`UPDATE secrets SET ns=?,ciphertext=?,dek_wrapped=?,bindings=? WHERE id=?`, name, newCT, newWrapped, string(bb), sid); e != nil {
			adminErrOut(w, http.StatusInternalServerError, "could not move selected secret")
			return
		}
		moved++
	}
	if e = tx.Commit(); e != nil {
		adminErrOut(w, http.StatusInternalServerError, "could not commit move")
		return
	}
	for _, sid := range selected {
		s.audit("admin", name, "secret-associate", sid, "", "ok", s.sourceIP(r))
	}
	http.Redirect(w, r, "/admin/projects/"+name, http.StatusSeeOther)
	_ = moved
}

// adminProjectClientNew 给项目添加一个接入方。
func (s *Server) adminProjectClientNew(w http.ResponseWriter, r *http.Request, name string) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	if !s.projectExists(name) {
		adminErrOut(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method == http.MethodGet {
		type item struct{ ID, Label, Provider, Hosts string }
		var list []item
		rows, e := s.S.DB.Query(`SELECT id,label,provider,bindings FROM secrets WHERE ns=? AND status='active' ORDER BY label`, name)
		if e != nil {
			adminErrOut(w, http.StatusInternalServerError, "internal error")
			return
		}
		for rows.Next() {
			var v item
			var raw string
			if rows.Scan(&v.ID, &v.Label, &v.Provider, &raw) == nil {
				var bd Binding
				_ = json.Unmarshal([]byte(raw), &bd)
				v.Provider = providerLabel(v.Provider)
				v.Hosts = strings.Join(bd.Hosts, ", ")
				list = append(list, v)
			}
		}
		rows.Close()
		render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>添加接入方</title><h1>添加接入方</h1><p class="lead">给要用这个项目的人或程序发一张通行证。令牌只显示一次。</p><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>名称 <input name="name" pattern="[A-Za-z0-9._-]{1,64}" autocomplete="off" required><small class="hint">同一个项目里不能重名，例如 ci 或 blog-worker。</small></label><label>备注（可选） <input name="note" maxlength="100" autocomplete="off"><small class="hint">最多 100 字，写清楚是谁在用。</small></label><h2>可使用的密钥</h2>{{if .Items}}<div class="group">{{range .Items}}<label class="check"><input type="checkbox" name="secret" value="{{.ID}}" checked><span class="t">{{.Label}}<small>{{.Provider}}{{if .Hosts}} · {{.Hosts}}{{end}}</small></span></label>{{end}}</div><p class="hint">至少选一个。没勾选的密钥，这个接入方用不了。</p>{{else}}<p class="hint">这个项目还没有密钥，先去「新建密钥」或「从未关联移入」。</p>{{end}}<details><summary>高级</summary><label class="check"><input type="checkbox" name="allow_resolve"><span class="t">允许取出明文（命令注入 / git 需要）<small class="hint">给 AI 用请不要勾选。</small></span></label><label>限制来源 IP（可选） <input name="cidrs" autocomplete="off" placeholder="10.0.0.0/8, 192.168.1.5"><small class="hint">留空表示不限来源；单个 IP 会自动补成 /32 或 /128。</small></label></details><div class="bar"><button class="btn block">生成通行证</button></div></form>`, map[string]any{"CSRF": sess.csrf, "Name": name, "Items": list})
		return
	}
	if r.Method != http.MethodPost {
		adminErrOut(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	_ = r.ParseForm()
	clientName := strings.TrimSpace(r.Form.Get("name"))
	note := strings.TrimSpace(r.Form.Get("note"))
	if !namePattern.MatchString(clientName) {
		adminErrOut(w, http.StatusBadRequest, "名称只能用字母、数字、点、下划线、连字符，最多 64 位")
		return
	}
	if runeLen(note) > clientNoteMaxRunes {
		adminErrOut(w, http.StatusBadRequest, fmt.Sprintf("备注最多 %d 字", clientNoteMaxRunes))
		return
	}
	allowResolve := r.Form.Get("allow_resolve") == "on"
	cidrs, cidrErr := normalizeCIDRs(r.Form.Get("cidrs"))
	if cidrErr != nil {
		adminErrOut(w, http.StatusBadRequest, "限制来源 IP 无效：请填写 IP 或 CIDR，多个用英文逗号分隔，例如 10.0.0.0/8, 192.168.1.5")
		return
	}
	cidrList := strings.Join(cidrs, ",")
	selected := r.Form["secret"]
	if len(selected) == 0 {
		adminErrOut(w, http.StatusBadRequest, "请至少选择一个密钥")
		return
	}
	var dup int
	if e := s.S.DB.QueryRow(`SELECT count(*) FROM clients WHERE ns=? AND name=?`, name, clientName).Scan(&dup); e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	if dup != 0 {
		adminErrOut(w, http.StatusBadRequest, "同一个项目里已经有同名的接入方")
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
	clientID, e := randomID()
	if e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	scopes := "secrets:list,fetch"
	if allowResolve {
		scopes = "secrets:list,resolve,fetch"
	}
	tx, e := s.S.DB.Begin()
	if e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, e = tx.Exec(`INSERT INTO clients(id,ns,name,token_hash,scopes,cidrs,expires_at,disabled,created_at,note) VALUES(?,?,?,?,?,?,'',0,?,?)`, clientID, name, clientName, sum[:], scopes, cidrList, now, note); e != nil {
		adminErrOut(w, http.StatusInternalServerError, "could not create client")
		return
	}
	for _, sid := range selected {
		var secretNS string
		if e = tx.QueryRow(`SELECT ns FROM secrets WHERE id=? AND status='active'`, sid).Scan(&secretNS); e != nil || secretNS != name {
			adminErrOut(w, http.StatusBadRequest, "selected secret unavailable")
			return
		}
	}
	if e = authorizeProjectSecrets(tx, name, clientID, selected, allowResolve); e != nil {
		adminErrOut(w, http.StatusInternalServerError, "could not authorize selected secrets")
		return
	}
	if e = tx.Commit(); e != nil {
		adminErrOut(w, http.StatusInternalServerError, "could not commit client")
		return
	}
	s.audit("admin", name, "client-create", clientID, "", "ok", s.sourceIP(r))
	for _, sid := range selected {
		s.audit("admin", name, "secret-associate", sid, "", "ok", s.sourceIP(r))
	}
	s.renderPassport(w, passportView{
		Project:      name,
		Title:        "接入方已创建",
		Token:        token,
		AllowResolve: allowResolve,
		CIDRs:        strings.Join(cidrs, ", "),
		Count:        len(selected),
		ScopeNote:    "本次勾选的密钥已授权给这个接入方；未勾选的密钥它用不了，其他接入方的权限不受影响。",
		BackHref:     "/admin/projects/" + name,
		BackLabel:    "返回项目",
	})
}

// authorizeProjectSecrets 在同一个事务里处理「空授权列表」的语义：
// 先把「对全项目开放」（allowed_clients 为空且 no_client_access=false）的密钥显式化——
// 有既有接入方就写成它们，没有就改成 no_client_access=true（否则空列表仍然等于对全项目开放）；
// 再给本次勾选的密钥追加新接入方，谁都不会被静默撤权。一步式「接入项目」与项目页共用本函数。
func authorizeProjectSecrets(tx *sql.Tx, project, newClientID string, selected []string, allowResolve bool) error {
	existing := []string{}
	rows, err := tx.Query(`SELECT id FROM clients WHERE ns=? AND disabled=0`, project)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil && id != newClientID {
			existing = append(existing, id)
		}
	}
	rows.Close()
	chosen := map[string]bool{}
	for _, sid := range selected {
		chosen[sid] = true
	}
	srows, err := tx.Query(`SELECT id,bindings FROM secrets WHERE ns=? AND status='active'`, project)
	if err != nil {
		return err
	}
	type secretRow struct{ id, bindings string }
	var list []secretRow
	for srows.Next() {
		var r secretRow
		if srows.Scan(&r.id, &r.bindings) == nil {
			list = append(list, r)
		}
	}
	srows.Close()
	for _, r := range list {
		var bd Binding
		if json.Unmarshal([]byte(r.bindings), &bd) != nil {
			return errors.New("invalid stored policy")
		}
		changed := false
		if len(bd.AllowedClients) == 0 && !bd.NoClientAccess {
			if len(existing) == 0 {
				bd.NoClientAccess = true
			} else {
				bd.AllowedClients = append([]string(nil), existing...)
			}
			changed = true
		}
		if chosen[r.id] {
			if allowResolve {
				bd.AllowResolve = true
			}
			bd.NoClientAccess = false
			found := false
			for _, v := range bd.AllowedClients {
				if v == newClientID {
					found = true
				}
			}
			if !found {
				bd.AllowedClients = append(bd.AllowedClients, newClientID)
			}
			changed = true
		}
		if !changed {
			continue
		}
		bb, _ := json.Marshal(bd)
		if _, err := tx.Exec(`UPDATE secrets SET bindings=? WHERE id=?`, string(bb), r.id); err != nil {
			return err
		}
	}
	return nil
}
