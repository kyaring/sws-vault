package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	vaultcrypto "github.com/kyaring/sws-vault/internal/crypto"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var namePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func (s *Server) adminNamespaces(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminSession(w, r); !ok {
		return
	}
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		name := strings.TrimSpace(r.Form.Get("name"))
		if strings.HasPrefix(name, "_") {
			adminErrOut(w, 400, "这是系统保留名称")
			return
		}
		if !namePattern.MatchString(name) {
			adminErrOut(w, 400, "invalid project")
			return
		}
		id, e := randomID()
		if e != nil {
			adminErrOut(w, 500, "internal error")
			return
		}
		_, e = s.S.DB.Exec(`INSERT INTO namespaces(id,name,created_at) VALUES(?,?,?)`, id, name, time.Now().UTC().Format(time.RFC3339))
		if e != nil {
			adminErrOut(w, 400, "project already exists")
			return
		}
		s.audit("admin", name, "project-create", "", "", "ok", s.sourceIP(r))
		http.Redirect(w, r, "/admin/projects/"+name, http.StatusSeeOther)
		return
	}
	// 旧的「项目」页已并入 /admin/projects，浏览时直接跳转。
	http.Redirect(w, r, "/admin/projects", http.StatusSeeOther)
}

func (s *Server) adminClients(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminSession(w, r); !ok {
		return
	}
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		ns := strings.TrimSpace(r.Form.Get("ns"))
		name := strings.TrimSpace(r.Form.Get("name"))
		scopes := strings.TrimSpace(r.Form.Get("scopes"))
		cidrs := strings.TrimSpace(r.Form.Get("cidrs"))
		expires := strings.TrimSpace(r.Form.Get("expires"))
		if strings.HasPrefix(ns, "_") {
			adminErrOut(w, 400, "这是系统保留名称")
			return
		}
		if !namePattern.MatchString(ns) || !namePattern.MatchString(name) || scopes == "" {
			adminErrOut(w, 400, "invalid client fields")
			return
		}
		valid := map[string]bool{"secrets:list": true, "secrets:write": true, "fetch": true, "resolve": true, "intents:create": true}
		for _, v := range strings.Split(scopes, ",") {
			if !valid[strings.TrimSpace(v)] {
				adminErrOut(w, 400, "invalid scope")
				return
			}
		}
		if cidrs != "" {
			for _, v := range strings.Split(cidrs, ",") {
				if _, _, e := net.ParseCIDR(strings.TrimSpace(v)); e != nil {
					adminErrOut(w, 400, "invalid CIDR")
					return
				}
			}
		}
		if expires != "" {
			if _, e := time.Parse(time.RFC3339, expires); e != nil {
				adminErrOut(w, 400, "expiry must be RFC3339")
				return
			}
		}
		raw := make([]byte, 32)
		if _, e := rand.Read(raw); e != nil {
			adminErrOut(w, 500, "internal error")
			return
		}
		token := "swsv_" + base64.RawURLEncoding.EncodeToString(raw)
		h := sha256.Sum256([]byte(token))
		id, e := vaultcrypto.Random(16)
		if e != nil {
			adminErrOut(w, 500, "internal error")
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		_, e = s.S.DB.Exec(`INSERT INTO namespaces(id,name,created_at) VALUES(?,?,?) ON CONFLICT(name) DO NOTHING`, hex.EncodeToString(id), ns, now)
		if e == nil {
			_, e = s.S.DB.Exec(`INSERT INTO clients(id,ns,name,token_hash,scopes,cidrs,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)`, hex.EncodeToString(id), ns, name, h[:], scopes, cidrs, expires, now)
		}
		for i := range raw {
			raw[i] = 0
		}
		if e != nil {
			adminErrOut(w, 400, "client could not be created")
			return
		}
		s.audit("admin", ns, "client-create", "", "", "ok", s.sourceIP(r))
		render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><h1>接入方已创建</h1><p>令牌只显示这一次。请立即保存到受保护的环境注入中。</p><pre>{{.Token}}</pre><a href="/admin/projects">返回项目</a></html>`, map[string]string{"Token": token})
		return
	}
	// A4：旧的「客户端」列表页删除，浏览时直接去项目标签；创建（POST）保留原处理。
	http.Redirect(w, r, "/admin/projects", http.StatusSeeOther)
}
func (s *Server) adminBindings(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/admin/secrets/"), "/bindings")
	if !namePattern.MatchString(id) {
		adminErrOut(w, 404, "not found")
		return
	}
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		hosts := []string{}
		for _, v := range strings.Split(r.Form.Get("hosts"), ",") {
			if v = strings.TrimSpace(v); v != "" {
				hosts = append(hosts, v)
			}
		}
		for _, host := range hosts {
			if !validHostBinding(host) {
				adminErrOut(w, 400, "invalid host binding")
				return
			}
		}
		var headers map[string]string
		if raw := strings.TrimSpace(r.Form.Get("headers")); raw != "" {
			if json.Unmarshal([]byte(raw), &headers) != nil {
				adminErrOut(w, 400, "invalid headers")
				return
			}
		}
		var existingRaw string
		_ = s.S.DB.QueryRow(`SELECT bindings FROM secrets WHERE id=? AND status='active'`, id).Scan(&existingRaw)
		var existing Binding
		_ = json.Unmarshal([]byte(existingRaw), &existing)
		username := strings.TrimSpace(r.Form.Get("username"))
		if username == mask(existing.Username) {
			username = existing.Username
		}
		allowedClients := splitCSV(r.Form.Get("allowed_clients"))
		// 原来「尚未授权给任何接入方」的密钥，留空保存后必须保持这个状态；
		// 一旦填了 allowed_clients，就表示改为显式授权。
		b, _ := json.Marshal(Binding{Username: username, AllowedClients: allowedClients, NoClientAccess: existing.NoClientAccess && len(allowedClients) == 0, Hosts: hosts, Headers: headers, AllowResolve: r.Form.Get("allow_resolve") == "on", AllowPrivate: r.Form.Get("allow_private") == "on", AllowHTTP: r.Form.Get("allow_http") == "on"})
		res, e := s.S.DB.Exec(`UPDATE secrets SET bindings=? WHERE id=? AND status='active'`, string(b), id)
		if e != nil {
			adminErrOut(w, 500, "internal error")
			return
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			adminErrOut(w, 404, "not found")
			return
		}
		s.audit("admin", "", "binding-update", id, "", "ok", s.sourceIP(r))
		http.Redirect(w, r, "/admin/secrets/"+id, http.StatusSeeOther)
		return
	}
	var ns, label, providerName, b string
	if e := s.S.DB.QueryRow(`SELECT ns,label,provider,bindings FROM secrets WHERE id=? AND status='active'`, id).Scan(&ns, &label, &providerName, &b); e != nil {
		adminErrOut(w, 404, "not found")
		return
	}
	var bd Binding
	_ = json.Unmarshal([]byte(b), &bd)
	headers, _ := json.Marshal(bd.Headers)
	render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><title>修改使用范围</title><h1>修改使用范围：{{.Label}}</h1>`+bindingsFormTemplate+`</html>`, map[string]any{"CSRF": sess.csrf, "Label": label, "Hosts": strings.Join(bd.Hosts, ","), "Headers": string(headers), "Username": mask(bd.Username), "AllowedClients": strings.Join(bd.AllowedClients, ","), "AllowResolve": bd.AllowResolve, "AllowPrivate": bd.AllowPrivate, "AllowHTTP": bd.AllowHTTP, "NoClientAccess": bd.NoClientAccess, "FormAction": "/admin/secrets/" + id + "/bindings"})
	_ = ns
	_ = providerName
}

// auditActionLabel / auditResultLabel 把审计里的英文动作与结果翻成面板上显示的中文（I4）。
func auditActionLabel(action string) string {
	if v, ok := auditActionLabels[action]; ok {
		return v
	}
	return action
}

func auditResultLabel(result string) string {
	if v, ok := auditResultLabels[result]; ok {
		return v
	}
	return result
}

var auditActionLabels = map[string]string{
	"fetch":               "代发",
	"resolve":             "取明文",
	"list":                "列表",
	"write":               "新建密钥",
	"rotate":              "轮换",
	"login":               "登录",
	"logout":              "退出",
	"client-create":       "新建接入方",
	"client-disable":      "停用接入方",
	"client-update":       "修改接入方",
	"client-regenerate":   "重新生成通行证",
	"project-create":      "新建项目",
	"project-description": "改项目简介",
	"secret-associate":    "放入项目",
	"secret-disable":      "停用密钥",
	"binding-update":      "改使用范围",
	"intent-create":       "生成录入链接",
	"admin.grant.update":  "改授权",
	"totp-enrolled":       "两步验证",
	"password-changed":    "改密码",
}

var auditResultLabels = map[string]string{
	"ok":       "成功",
	"failed":   "失败",
	"rejected": "被拒绝",
	"locked":   "已锁定",
	"denied":   "被拒绝",
}

func (s *Server) adminAudit(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	ns, actor, from, to := r.URL.Query().Get("ns"), r.URL.Query().Get("actor"), r.URL.Query().Get("from"), r.URL.Query().Get("to")
	displayNS := ns
	if ns == "未归入项目" {
		ns = unassignedNS
	}
	if ns == unassignedNS {
		displayNS = "未归入项目"
	}
	where := []string{"1=1"}
	args := []any{}
	if ns != "" {
		where = append(where, "ns=?")
		args = append(args, ns)
	}
	if actor != "" {
		where = append(where, "actor=?")
		args = append(args, actor)
	}
	if from != "" {
		if _, e := time.Parse(time.RFC3339, from); e != nil {
			adminErrOut(w, 400, "from must be RFC3339")
			return
		}
		where = append(where, "at>=?")
		args = append(args, from)
	}
	if to != "" {
		if _, e := time.Parse(time.RFC3339, to); e != nil {
			adminErrOut(w, 400, "to must be RFC3339")
			return
		}
		where = append(where, "at<=?")
		args = append(args, to)
	}
	clause := strings.Join(where, " AND ")
	var total int
	if e := s.S.DB.QueryRow("SELECT count(*) FROM audit WHERE "+clause, args...).Scan(&total); e != nil {
		adminErrOut(w, 500, "internal error")
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	if page > 10000 {
		page = 10000
	}
	rows, e := s.S.DB.Query("SELECT at,actor,ns,secret_id,action,target_host,result,source_ip FROM audit WHERE "+clause+" ORDER BY id DESC LIMIT 50 OFFSET ?", append(args, (page-1)*50)...)
	if e != nil {
		adminErrOut(w, 500, "internal error")
		return
	}
	defer rows.Close()
	type item struct{ At, Actor, NS, ID, Action, Host, Result, IP string }
	var list []item
	for rows.Next() {
		var v item
		if rows.Scan(&v.At, &v.Actor, &v.NS, &v.ID, &v.Action, &v.Host, &v.Result, &v.IP) == nil {
			if v.NS == unassignedNS {
				v.NS = "未归入项目"
			}
			v.Action = auditActionLabel(v.Action)
			v.Result = auditResultLabel(v.Result)
			list = append(list, v)
		}
	}
	mk := func(p int) string {
		v := url.Values{}
		v.Set("page", strconv.Itoa(p))
		if ns != "" {
			v.Set("ns", ns)
		}
		if actor != "" {
			v.Set("actor", actor)
		}
		if from != "" {
			v.Set("from", from)
		}
		if to != "" {
			v.Set("to", to)
		}
		return "/admin/audit?" + v.Encode()
	}
	prev, next := "", ""
	if page > 1 {
		prev = mk(page - 1)
	}
	if page*50 < total {
		next = mk(page + 1)
	}
	render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><h1>审计事件</h1><form method="get"><label>项目<input name="ns" value="{{.NS}}"></label><label>操作者<input name="actor" value="{{.Actor}}"></label><label>起始时间 RFC3339<input name="from" value="{{.From}}"></label><label>结束时间 RFC3339<input name="to" value="{{.To}}"></label><button>筛选</button></form><p>第 {{.Page}} 页，共 {{.Total}} 条</p><table><tr><th>时间</th><th>操作者</th><th>项目</th><th>ID</th><th>动作</th><th>主机</th><th>结果</th><th>来源 IP</th></tr>{{range .Items}}<tr><td>{{.At}}</td><td>{{.Actor}}</td><td>{{.NS}}</td><td>{{.ID}}</td><td>{{.Action}}</td><td>{{.Host}}</td><td>{{.Result}}</td><td>{{.IP}}</td></tr>{{end}}</table>{{if .Prev}}<a href="{{.Prev}}">上一页</a>{{end}} {{if .Next}}<a href="{{.Next}}">下一页</a>{{end}} <a href="/admin/">返回</a></html>`, map[string]any{"CSRF": sess.csrf, "Items": list, "Page": page, "Total": total, "Prev": prev, "Next": next, "NS": displayNS, "Actor": actor, "From": from, "To": to})
}
func (s *Server) adminRotateSecret(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/admin/secrets/"), "/rotate")
	if !namePattern.MatchString(id) {
		adminErrOut(w, 404, "not found")
		return
	}
	var ns, label, prov, typ, b string
	if e := s.S.DB.QueryRow(`SELECT ns,label,provider,type,bindings FROM secrets WHERE id=? AND status='active'`, id).Scan(&ns, &label, &prov, &typ, &b); e != nil {
		adminErrOut(w, 404, "not found")
		return
	}
	if r.Method == http.MethodGet {
		render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><title>轮换凭据</title><h1>轮换凭据：{{.Label}}</h1><form method="post" action="/admin/secrets/`+id+`/rotate"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>新值 <input type="password" name="value" autocomplete="off" required></label><label>验证 URL / Gitea base_url <input name="base_url"></label><label>保存前验证 <input type="checkbox" name="verify"></label><button>轮换</button></form></html>`, map[string]string{"CSRF": sess.csrf, "Label": label})
		return
	}
	if r.Method != http.MethodPost {
		adminErrOut(w, 405, "method not allowed")
		return
	}
	_ = r.ParseForm()
	value := r.Form.Get("value")
	if value == "" {
		adminErrOut(w, 400, "invalid value")
		return
	}
	var bd Binding
	_ = json.Unmarshal([]byte(b), &bd)
	q := SecretRequest{NS: ns, Label: label, Provider: prov, Type: typ, Username: bd.Username, Value: value, Bindings: bd}
	if r.Form.Get("verify") == "on" {
		if e := s.verifySecret(q, r.Form.Get("base_url")); e != nil {
			adminErrOut(w, 400, e.Error())
			return
		}
	}
	m, e := s.save(q, true, id)
	if e != nil {
		adminErrOut(w, 400, "rotation failed")
		return
	}
	s.audit("admin", ns, "rotate", m.ID, "", "ok", s.sourceIP(r))
	http.Redirect(w, r, "/admin/secrets/"+m.ID, http.StatusSeeOther)
}
func (s *Server) adminDisableSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		adminErrOut(w, 405, "method not allowed")
		return
	}
	if _, ok := s.adminSession(w, r); !ok {
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/admin/secrets/"), "/disable")
	res, e := s.S.DB.Exec(`UPDATE secrets SET status='revoked' WHERE id=? AND status='active'`, id)
	if e != nil {
		adminErrOut(w, 500, "internal error")
		return
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		adminErrOut(w, 404, "not found")
		return
	}
	s.audit("admin", "", "secret-disable", id, "", "ok", s.sourceIP(r))
	http.Redirect(w, r, "/admin/secrets/"+id, http.StatusSeeOther)
}
func (s *Server) adminDisableClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		adminErrOut(w, 405, "method not allowed")
		return
	}
	if _, ok := s.adminSession(w, r); !ok {
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/admin/clients/"), "/disable")
	var ns string
	if e := s.S.DB.QueryRow(`SELECT ns FROM clients WHERE id=?`, id).Scan(&ns); e != nil {
		adminErrOut(w, 404, "not found")
		return
	}
	res, e := s.S.DB.Exec(`UPDATE clients SET disabled=1 WHERE id=? AND disabled=0`, id)
	if e != nil {
		adminErrOut(w, 500, "internal error")
		return
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		adminErrOut(w, 404, "not found")
		return
	}
	s.audit("admin", "", "client-disable", id, "", "ok", s.sourceIP(r))
	http.Redirect(w, r, "/admin/projects/"+ns+"/clients/"+id, http.StatusSeeOther)
}
func (s *Server) adminIntentNew(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><h1>创建一次性录入链接</h1><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>项目 <input name="ns" value="default" required></label><label>标签 <input name="label" required></label><button class="btn block">创建链接</button></form></html>`, map[string]string{"CSRF": sess.csrf})
		return
	}
	if r.Method != http.MethodPost {
		adminErrOut(w, 405, "method not allowed")
		return
	}
	_ = r.ParseForm()
	label := strings.TrimSpace(r.Form.Get("label"))
	if label == "" || len(label) > 128 {
		adminErrOut(w, 400, "invalid label")
		return
	}
	ns := strings.TrimSpace(r.Form.Get("ns"))
	if ns == "" {
		ns = "default"
	}
	if strings.HasPrefix(ns, "_") {
		adminErrOut(w, 400, "这是系统保留名称")
		return
	}
	if !namePattern.MatchString(ns) {
		adminErrOut(w, 400, "invalid project")
		return
	}
	link, e := s.createIntent(ns, label)
	if e != nil {
		adminErrOut(w, 500, "internal error")
		return
	}
	s.audit("admin", ns, "intent-create", "", "", "ok", s.sourceIP(r))
	render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><h1>一次性链接已创建</h1><p>链接有效期 10 分钟，只显示这一次。</p><pre>{{.URL}}</pre><a href="/admin/">返回</a></html>`, map[string]string{"URL": link})
}

func splitCSV(v string) []string {
	var out []string
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// createIntent 生成一次性录入链接（10 分钟有效），返回可展示的完整链接。
func (s *Server) createIntent(ns, label string) (string, error) {
	raw, e := vaultcrypto.Random(32)
	if e != nil {
		return "", e
	}
	token := vaultcrypto.Encode(raw)
	for i := range raw {
		raw[i] = 0
	}
	h := sha256.Sum256([]byte(token))
	now := time.Now().UTC()
	if _, e = s.S.DB.Exec(`INSERT INTO namespaces(id,name,created_at) VALUES(?,?,?) ON CONFLICT(name) DO NOTHING`, hex.EncodeToString(h[:16]), ns, now.Format(time.RFC3339)); e != nil {
		return "", e
	}
	if _, e = s.S.DB.Exec(`INSERT INTO intents(token_hash,ns,label,expires_at) VALUES(?,?,?,?)`, h[:], ns, label, now.Add(10*time.Minute).Format(time.RFC3339)); e != nil {
		return "", e
	}
	link := "/i/" + token
	if base := s.C.PublicBaseURL; base != "" {
		link = base + link
	}
	return link, nil
}

// adminProjectIntentNew 在项目里生成录入链接（E）：项目字段固定为本项目。
func (s *Server) adminProjectIntentNew(w http.ResponseWriter, r *http.Request, name string) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	if !s.projectExists(name) {
		adminErrOut(w, 404, "not found")
		return
	}
	if r.Method == http.MethodGet {
		render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>生成录入链接</title><h1>生成录入链接</h1><p class="lead">链接 10 分钟内有效，对方点开就能把密钥填进 {{.Name}}。</p><form method="post" action="/admin/projects/{{.Name}}/intents/new"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>标签 <input name="label" required maxlength="128" autocomplete="off"><small class="hint">给这个密钥起个名字，方便之后认出来。</small></label><button class="btn block">生成录入链接</button></form>`, map[string]any{"CSRF": sess.csrf, "Name": name})
		return
	}
	if r.Method != http.MethodPost {
		adminErrOut(w, 405, "method not allowed")
		return
	}
	_ = r.ParseForm()
	label := strings.TrimSpace(r.Form.Get("label"))
	if label == "" || len(label) > 128 {
		adminErrOut(w, 400, "invalid label")
		return
	}
	link, e := s.createIntent(name, label)
	if e != nil {
		adminErrOut(w, 500, "internal error")
		return
	}
	s.audit("admin", name, "intent-create", "", "", "ok", s.sourceIP(r))
	render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>录入链接</title><h1>录入链接已生成</h1><p>链接有效期 10 分钟，只显示这一次。</p><pre>{{.URL}}</pre><a href="/admin/projects/{{.Name}}">返回项目</a>`, map[string]string{"URL": link, "Name": name})
}
