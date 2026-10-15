package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	vaultcrypto "github.com/kyaring/sws-vault/internal/crypto"
	"github.com/kyaring/sws-vault/internal/provider"
)

const unassignedNS = "_unassigned"

var projectNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

func (s *Server) adminDashboard(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	type project struct {
		Name             string
		Secrets, Clients int
	}
	rows, err := s.S.DB.Query(`SELECT n.name,(SELECT count(*) FROM secrets x WHERE x.ns=n.name AND x.status='active'),(SELECT count(*) FROM clients c WHERE c.ns=n.name AND c.disabled=0) FROM namespaces n WHERE n.name<>? AND substr(n.name,1,1)<>'_' ORDER BY n.name`, unassignedNS)
	if err != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()
	var projects []project
	for rows.Next() {
		var item project
		if rows.Scan(&item.Name, &item.Secrets, &item.Clients) == nil {
			projects = append(projects, item)
		}
	}
	var secretCount, projectCount, unassigned int
	var lastUsed string
	if err := s.S.DB.QueryRow(`SELECT count(*) FROM secrets WHERE status='active'`).Scan(&secretCount); err != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.S.DB.QueryRow(`SELECT count(*) FROM namespaces WHERE name<>? AND substr(name,1,1)<>'_'`, unassignedNS).Scan(&projectCount); err != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.S.DB.QueryRow(`SELECT count(*) FROM secrets WHERE ns=? AND status='active'`, unassignedNS).Scan(&unassigned); err != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.S.DB.QueryRow(`SELECT COALESCE(max(last_used_at), '') FROM secrets WHERE last_used_at<>''`).Scan(&lastUsed); err != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	if lastUsed != "" {
		lastUsed = relativeUseTime(lastUsed)
	}
	data := map[string]any{"CSRF": sess.csrf, "Projects": projects, "Unassigned": unassigned, "SecretCount": secretCount, "ProjectCount": projectCount, "LastUsed": lastUsed}
	render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><title>保险库</title>
<h1>保险库</h1><p class="lead">{{.SecretCount}} 个有效密钥 · {{.ProjectCount}} 个项目{{if .LastUsed}} · 最近一次调用 {{.LastUsed}}{{end}}</p>
<div class="actions"><a class="action primary" href="/admin/secrets/new"><span class="ico" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></span><span><b>新建</b>存一个密钥</span></a><a class="action" href="/admin/quick/project"><span class="ico" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.1 0l2-2a5 5 0 0 0-7.1-7.1l-1.2 1.2M14 11a5 5 0 0 0-7.1 0l-2 2A5 5 0 0 0 12 20.1l1.2-1.2" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg></span><span><b>接入项目</b>生成令牌和配置</span></a></div>
{{if gt .Unassigned 0}}<h2>需要处理</h2><div class="group"><a class="row" href="/admin/advanced/secrets?ns=_unassigned"><span class="ico" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M3 7h7l2 2h9v10H3z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg></span><span class="t">未关联密钥<small>还没给任何项目，暂不可调用</small></span><span class="badge">{{.Unassigned}}</span></a></div>{{end}}
<h2>项目</h2>{{if .Projects}}<div class="group">{{range .Projects}}<a class="row" href="/admin/advanced/secrets?ns={{.Name}}"><span class="dot" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M3 7 12 3l9 4-9 4zM3 7v10l9 4 9-4V7M12 11v10" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/></svg></span><span class="t">{{.Name}}<small>{{.Secrets}} 个密钥 · {{.Clients}} 个客户端</small></span></a>{{end}}</div>{{else}}<p class="hint">还没有项目。选择「接入项目」开始。</p>{{end}}
<h2>更多</h2><div class="group"><a class="row" href="/admin/advanced/secrets"><span class="dot" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="8" cy="15" r="4" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="m11 12 8-8 2 2-2 2 2 2-3 3-2-2-3 3" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg></span><span class="t">所有密钥</span></a><a class="row" href="/admin/audit"><span class="dot" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M12 7v5l3 2" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg></span><span class="t">审计事件</span></a><a class="row" href="/admin/advanced"><span class="dot" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8ZM19 13.5l2-1.5-2-1.5-.7-2.2-2.5-.2L14.5 6 12 5l-2.5 1-.8 2.1-2.5.2-.7 2.2-2 1.5 2 1.5.7 2.2 2.5.2.8 2.1 2.5 1 2.5-1 .8-2.1 2.5-.2z" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/></svg></span><span class="t">高级功能</span></a></div>
</html>`, data)
}

func relativeUseTime(value string) string {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		if parsed, err = time.Parse(time.RFC3339, value); err != nil {
			return value
		}
	}
	elapsed := time.Since(parsed)
	if elapsed < time.Minute {
		return "刚刚"
	}
	if elapsed < time.Hour {
		return fmt.Sprintf("%d 分钟前", int(elapsed.Minutes()))
	}
	if elapsed < 24*time.Hour {
		return fmt.Sprintf("%d 小时前", int(elapsed.Hours()))
	}
	return fmt.Sprintf("%d 天前", int(elapsed.Hours()/24))
}

func (s *Server) adminAdvanced(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>高级功能</title><h1>高级</h1><div class="group"><a class="row" href="/admin/advanced/secrets"><span class="ico" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 3 4 6v5c0 5 3 8 8 10 5-2 8-5 8-10V6z" fill="none" stroke="currentColor" stroke-width="1.7"/></svg></span><span class="t">密钥列表</span></a><a class="row" href="/admin/namespaces"><span class="ico" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M3 7h7l2 2h9v10H3z" fill="none" stroke="currentColor" stroke-width="1.7"/></svg></span><span class="t">项目管理</span></a><a class="row" href="/admin/clients"><span class="ico" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="9" cy="8" r="3" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="M3 20v-2a6 6 0 0 1 12 0v2M17 5a3 3 0 0 1 0 6M18 15a5 5 0 0 1 3 5" fill="none" stroke="currentColor" stroke-width="1.7"/></svg></span><span class="t">客户端</span></a><a class="row" href="/admin/audit"><span class="ico" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="M12 7v5l3 2" fill="none" stroke="currentColor" stroke-width="1.7"/></svg></span><span class="t">审计事件</span></a><a class="row" href="/admin/intents/new"><span class="ico" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="4" y="3" width="16" height="18" rx="2" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="M8 8h8M8 12h8M8 16h5" stroke="currentColor" stroke-width="1.7"/></svg></span><span class="t">一次性录入链接</span></a></div><a class="back" href="/admin/">返回首页</a></html>`, map[string]string{"CSRF": sess.csrf})
}

func (s *Server) adminNewSecret(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		rows, e := s.S.DB.Query(`SELECT name FROM namespaces WHERE name<>? ORDER BY name`, unassignedNS)
		if e != nil {
			adminErrOut(w, 500, "internal error")
			return
		}
		defer rows.Close()
		var names []string
		for rows.Next() {
			var n string
			if rows.Scan(&n) == nil {
				names = append(names, n)
			}
		}
		render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>新建密钥</title><link rel="stylesheet" href="/admin/assets/admin.css"><h1>新建</h1><p class="lead">粘贴后立即加密保存，密钥值不会再次显示。</p><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><fieldset class="choices"><legend>平台</legend><label class="choice"><input type="radio" name="provider" value="cloudflare-token" checked><span><i class="brand-cloudflare">CF</i><b>Cloudflare</b></span></label><label class="choice"><input type="radio" name="provider" value="github-pat"><span><i class="brand-github">GH</i><b>GitHub</b></span></label><label class="choice"><input type="radio" name="provider" value="gitea-token"><span><i class="brand-gitea">Gt</i><b>Gitea</b></span></label><label class="choice"><input type="radio" name="provider" value="generic"><span><i class="brand-generic">··</i><b>通用</b></span></label></fieldset><label>名称 <input name="label" required maxlength="128"></label><label>密钥值 <input type="password" name="value" autocomplete="off" required></label><label class="gitea-only">Gitea 地址（选择 Gitea 时必填，例如 https://git.example.com） <input name="gitea_address" autocomplete="url"><small class="hint">只会发往这个域名。</small></label><label class="gitea-only"><input type="checkbox" name="allow_http">允许 HTTP（仅在明确需要时启用）</label><label>关联项目（可选） <select name="project"><option value="">暂不关联</option>{{range .Projects}}<option value="{{.}}">{{.}}</option>{{end}}</select><small class="hint">不关联时，任何客户端都无法调用。</small></label><label class="generic-only">允许发往的域名（仅通用平台，逗号分隔） <input name="hosts" autocomplete="off"></label><label class="generic-only">Header 模板 JSON <input name="headers" autocomplete="off" placeholder="{&quot;Authorization&quot;:&quot;Bearer {v}&quot;}"></label><div class="bar"><button class="btn block">保存</button></div></form><p><a href="/admin/">取消</a></p>`, map[string]any{"CSRF": sess.csrf, "Projects": names})
		return
	}
	if r.Method != http.MethodPost {
		adminErrOut(w, 405, "method not allowed")
		return
	}
	_ = r.ParseForm()
	providerName := r.Form.Get("provider")
	project := strings.TrimSpace(r.Form.Get("project"))
	ns := unassignedNS
	if project != "" {
		if !projectNamePattern.MatchString(project) {
			adminErrOut(w, 400, "invalid project name")
			return
		}
		var n int
		if e := s.S.DB.QueryRow(`SELECT count(*) FROM namespaces WHERE name=?`, project).Scan(&n); e != nil || n == 0 {
			adminErrOut(w, 400, "project not found")
			return
		}
		ns = project
	}
	hosts := []string{}
	switch providerName {
	case "cloudflare-token", "github-pat":
		hosts = provider.DefaultHosts(providerName)
		if providerName == "github-pat" {
			hosts = append(hosts, "github.com")
		}
	case "gitea-token":
		address := strings.TrimSpace(r.Form.Get("gitea_address"))
		if address == "" {
			adminErrOut(w, 400, "Gitea 地址必填，请填写完整地址，例如 https://git.example.com")
			return
		}
		parsed, parseErr := url.Parse(address)
		if parseErr != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
			adminErrOut(w, 400, "Gitea 地址无效，请填写完整地址，例如 https://git.example.com")
			return
		}
		if parsed.Scheme != "https" && r.Form.Get("allow_http") != "on" {
			adminErrOut(w, 400, "Gitea 地址默认必须使用 https://；如确需 HTTP，请勾选「允许 HTTP」")
			return
		}
		if !validHostBinding(parsed.Host) {
			adminErrOut(w, 400, "Gitea 地址中的主机名无效，请填写例如 https://git.example.com")
			return
		}
		host := strings.ToLower(parsed.Hostname())
		hosts = []string{host}
	case "generic":
		for _, h := range strings.Split(r.Form.Get("hosts"), ",") {
			if h = strings.TrimSpace(h); h != "" {
				hosts = append(hosts, h)
			}
		}
	default:
		adminErrOut(w, 400, "invalid provider")
		return
	}
	if providerName == "generic" && len(hosts) == 0 {
		adminErrOut(w, 400, "allowed domain required for generic platform")
		return
	}
	q := SecretRequest{NS: ns, Label: strings.TrimSpace(r.Form.Get("label")), Provider: providerName, Type: "token", Value: r.Form.Get("value"), Bindings: Binding{Hosts: hosts, AllowResolve: true, AllowPrivate: r.Form.Get("allow_private") == "on", AllowHTTP: r.Form.Get("allow_http") == "on"}}
	if providerName == "generic" {
		q.Bindings.Headers = map[string]string{"Authorization": "Bearer {v}"}
		if raw := strings.TrimSpace(r.Form.Get("headers")); raw != "" {
			if json.Unmarshal([]byte(raw), &q.Bindings.Headers) != nil {
				adminErrOut(w, 400, "invalid header templates")
				return
			}
		}
	}
	if r.Form.Get("verify") == "on" {
		if e := s.verifySecret(q, r.Form.Get("base_url")); e != nil {
			adminErrOut(w, 400, e.Error())
			return
		}
	}
	m, e := s.save(q, false, "")
	if e != nil {
		adminErrOut(w, 400, "could not save secret")
		return
	}
	s.audit("admin", ns, "write", m.ID, "", "ok", s.sourceIP(r))
	slog.Info("admin secret stored", "namespace", ns, "secret_id", m.ID, "provider", providerName)
	w.Header().Set("Cache-Control", "no-store")
	association := "未关联"
	scopeNote := "该密钥位于未关联区，项目客户端不能读取；请通过「接入项目」选择目标客户端。"
	if providerName == "gitea-token" {
		scopeNote = "允许发往域名：" + strings.Join(hosts, ", ") + "。"
	}
	if project != "" {
		association = project
		if providerName == "gitea-token" {
			scopeNote += " 该项目内所有具备 resolve 权限的客户端均可使用此密钥。"
		} else {
			scopeNote = "该项目内所有具备 resolve 权限的客户端均可使用此密钥。"
		}
	}
	providerLabel := map[string]string{"cloudflare-token": "Cloudflare", "github-pat": "GitHub", "gitea-token": "Gitea", "generic": "通用"}[providerName]
	render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>已保存</title><div class="hero"><span class="seal" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="m5 12 4 4L19 6" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg></span><h1>已保存</h1></div><dl><div><dt>名称</dt><dd>{{.Label}}</dd></div><div><dt>平台</dt><dd>{{.Provider}}</dd></div><div><dt>关联状态</dt><dd>{{.Association}}</dd></div>{{if .Hosts}}<div><dt>允许发往</dt><dd>{{.Hosts}}</dd></div>{{end}}</dl><p>使用范围：{{.ScopeNote}}</p><p>密钥值不会再次显示。</p><div class="bar"><div class="bar-actions"><a class="btn secondary" href="/admin/">返回首页</a><a class="btn" href="/admin/quick/project">接入项目</a></div></div>`, map[string]string{"Label": q.Label, "Provider": providerLabel, "Association": association, "ScopeNote": scopeNote, "Hosts": strings.Join(hosts, ", ")})
}

func (s *Server) adminQuickProject(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		project := strings.TrimSpace(r.URL.Query().Get("project"))
		client := strings.TrimSpace(r.URL.Query().Get("client"))
		if client == "" {
			client = "default"
		}
		if project == "" {
			render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><link rel="stylesheet" href="/admin/assets/admin.css"><title>接入项目</title><h1>接入项目</h1><p class="lead">第 1 步，共 2 步</p><p>先填写项目名，再选择要提供给项目的密钥。</p><form method="get" action="/admin/quick/project"><label>项目名（小写字母、数字、连字符） <input name="project" pattern="[a-z0-9][a-z0-9-]{0,63}" required></label><label>客户端名称 <input name="client" value="default" pattern="[A-Za-z0-9._-]{1,64}" required></label><button>下一步：选择密钥</button></form><a href="/admin/">取消</a>`, nil)
			return
		}
		if !projectNamePattern.MatchString(project) || !namePattern.MatchString(client) {
			adminErrOut(w, 400, "invalid project or client name")
			return
		}
		rows, e := s.S.DB.Query(`SELECT id,label,ns,provider,bindings FROM secrets WHERE status='active' AND (ns=? OR ns=?) ORDER BY label`, unassignedNS, project)
		if e != nil {
			adminErrOut(w, 500, "internal error")
			return
		}
		defer rows.Close()
		type item struct{ ID, Label, Project, Provider, Hosts string }
		var items []item
		providerNames := map[string]string{"cloudflare-token": "Cloudflare", "github-pat": "GitHub", "gitea-token": "Gitea", "generic": "通用"}
		for rows.Next() {
			var x item
			var rawBindings string
			if rows.Scan(&x.ID, &x.Label, &x.Project, &x.Provider, &rawBindings) == nil {
				var binding Binding
				_ = json.Unmarshal([]byte(rawBindings), &binding)
				x.Provider = providerNames[x.Provider]
				x.Hosts = strings.Join(binding.Hosts, ", ")
				items = append(items, x)
			}
		}
		var unassignedItems, projectItems []item
		for _, item := range items {
			if item.Project == unassignedNS {
				unassignedItems = append(unassignedItems, item)
			} else {
				projectItems = append(projectItems, item)
			}
		}
		render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><link rel="stylesheet" href="/admin/assets/admin.css"><title>接入项目</title><h1>接入项目：{{.Project}}</h1><p class="lead">第 2 步，共 2 步</p><p>选择未关联密钥或已经属于此项目的密钥。提交后会创建一个新的客户端令牌。</p><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="project" value="{{.Project}}"><input type="hidden" name="client" value="{{.Client}}">{{if .UnassignedItems}}<h2>未关联</h2><div class="group">{{range .UnassignedItems}}<label class="check"><input type="checkbox" name="secret" value="{{.ID}}"><span>{{.Label}}<small>{{.Provider}}{{if .Hosts}} · {{.Hosts}}{{end}}</small></span></label>{{end}}</div>{{end}}{{if .ProjectItems}}<h2>已在此项目</h2><div class="group">{{range .ProjectItems}}<label class="check"><input type="checkbox" name="secret" value="{{.ID}}"><span>{{.Label}}<small>{{.Provider}}{{if .Hosts}} · {{.Hosts}}{{end}}</small></span></label>{{end}}</div>{{end}}{{if not .Items}}<p>暂无可选密钥。</p>{{end}}<details class="advanced"><summary>高级</summary><label class="check"><input type="checkbox" name="allow_resolve"><span>允许取出明文（命令注入 / git 需要）<small>给 AI 用请不要勾选。</small></span></label><label>限制来源 IP（可选）<input name="cidrs" autocomplete="off" placeholder="10.0.0.0/8, 192.168.1.5"><small class="hint">只有来自这些地址的调用会被接受；单个 IP 会自动补成 /32（IPv4）或 /128（IPv6）。</small></label></details><div class="bar"><button class="btn block selected-submit">生成项目配置</button></div></form>`, map[string]any{"CSRF": sess.csrf, "Items": items, "UnassignedItems": unassignedItems, "ProjectItems": projectItems, "Project": project, "Client": client})
		return
	}
	if r.Method != http.MethodPost {
		adminErrOut(w, 405, "method not allowed")
		return
	}
	_ = r.ParseForm()
	project := strings.TrimSpace(r.Form.Get("project"))
	clientName := strings.TrimSpace(r.Form.Get("client"))
	if !projectNamePattern.MatchString(project) || !namePattern.MatchString(clientName) {
		adminErrOut(w, 400, "invalid project or client name")
		return
	}
	// 安全默认值：快速流程默认只给 fetch，resolve 必须显式勾选；CIDR 在事务开始前校验，避免留下半成品。
	allowResolve := r.Form.Get("allow_resolve") == "on"
	cidrs, cidrErr := normalizeCIDRs(r.Form.Get("cidrs"))
	if cidrErr != nil {
		adminErrOut(w, 400, "限制来源 IP 无效：请填写 IP 或 CIDR，多个用英文逗号分隔，例如 10.0.0.0/8, 192.168.1.5")
		return
	}
	cidrList := strings.Join(cidrs, ",")
	scopes := "secrets:list,fetch"
	if allowResolve {
		scopes = "secrets:list,resolve,fetch"
	}
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		adminErrOut(w, 500, "internal error")
		return
	}
	token := "swsv_" + base64.RawURLEncoding.EncodeToString(raw)
	for i := range raw {
		raw[i] = 0
	}
	sum := sha256.Sum256([]byte(token))
	projectID, e := randomID()
	if e != nil {
		adminErrOut(w, 500, "internal error")
		return
	}
	clientID, e := randomID()
	if e != nil {
		adminErrOut(w, 500, "internal error")
		return
	}
	var projectExists int
	_ = s.S.DB.QueryRow(`SELECT count(*) FROM namespaces WHERE name=?`, project).Scan(&projectExists)
	tx, e := s.S.DB.Begin()
	if e != nil {
		adminErrOut(w, 500, "internal error")
		return
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339)
	_, e = tx.Exec(`INSERT INTO namespaces(id,name,created_at) VALUES(?,?,?) ON CONFLICT(name) DO NOTHING`, projectID, project, now)
	if e != nil {
		adminErrOut(w, 500, "could not create project")
		return
	}
	_, e = tx.Exec(`INSERT INTO clients(id,ns,name,token_hash,scopes,cidrs,expires_at,disabled,created_at) VALUES(?,?,?,?,?,?,'',0,?)`, clientID, project, clientName, sum[:], scopes, cidrList, now)
	if e != nil {
		adminErrOut(w, 500, "could not create client")
		return
	}
	selected := r.Form["secret"]
	for _, sid := range selected {
		var oldNS, typ string
		var version int
		var ct, wrapped []byte
		var b string
		e = tx.QueryRow(`SELECT ns,type,key_version,ciphertext,dek_wrapped,bindings FROM secrets WHERE id=? AND status='active'`, sid).Scan(&oldNS, &typ, &version, &ct, &wrapped, &b)
		if e != nil || (oldNS != unassignedNS && oldNS != project) {
			adminErrOut(w, 400, "selected secret unavailable")
			return
		}
		var bd Binding
		if json.Unmarshal([]byte(b), &bd) != nil {
			adminErrOut(w, 500, "invalid stored policy")
			return
		}
		dek, e := s.unwrapDEK(oldNS, sid, uint32(version), wrapped)
		if e != nil {
			adminErrOut(w, 500, "could not move selected secret")
			return
		}
		value, e := vaultcrypto.Open(dek, ct, vaultcrypto.SecretAAD(oldNS, sid, typ, uint32(version)))
		if e != nil {
			wipe(dek)
			adminErrOut(w, 500, "could not move selected secret")
			return
		}
		newCT, e := vaultcrypto.Seal(dek, value, vaultcrypto.SecretAAD(project, sid, typ, uint32(version)))
		if e != nil {
			wipe(dek)
			wipe(value)
			adminErrOut(w, 500, "could not move selected secret")
			return
		}
		newWrapped, e := s.wrapDEK(project, sid, uint32(version), dek)
		wipe(dek)
		wipe(value)
		if e != nil {
			adminErrOut(w, 500, "could not move selected secret")
			return
		}
		if allowResolve {
			bd.AllowResolve = true
		} else if oldNS == unassignedNS {
			bd.AllowResolve = false
		}
		if oldNS == unassignedNS {
			bd.AllowedClients = []string{clientID}
		} else if len(bd.AllowedClients) > 0 {
			found := false
			for _, v := range bd.AllowedClients {
				if v == clientID {
					found = true
				}
			}
			if !found {
				bd.AllowedClients = append(bd.AllowedClients, clientID)
			}
		}
		bb, _ := json.Marshal(bd)
		_, e = tx.Exec(`UPDATE secrets SET ns=?,ciphertext=?,dek_wrapped=?,bindings=? WHERE id=?`, project, newCT, newWrapped, string(bb), sid)
		if e != nil {
			adminErrOut(w, 500, "could not move selected secret")
			return
		}
	}
	if e = tx.Commit(); e != nil {
		adminErrOut(w, 500, "could not commit project")
		return
	}
	s.audit("admin", project, "project-client-create", "", "", "ok", s.sourceIP(r))
	for _, sid := range selected {
		s.audit("admin", project, "secret-associate", sid, "", "ok", s.sourceIP(r))
	}
	base := strings.TrimRight(s.C.PublicBaseURL, "/")
	baseURLMissing := base == ""
	if baseURLMissing {
		base = "<SWSV_URL>"
	}
	env := fmt.Sprintf("SWSV_URL=%s\nSWSV_TOKEN=%s\nSWSV_NS=%s", base, token, project)
	runExample := fmt.Sprintf("SWSV_URL=%s SWSV_TOKEN=%s SWSV_NS=%s swsvault run --secret vault:%s/<secret-id> -- <command>", base, token, project, project)
	gitExample := fmt.Sprintf("git config --global credential.helper '!SWSV_URL=%s SWSV_TOKEN=%s SWSV_NS=%s swsvault git-credential'", base, token, project)
	fetchExample := fmt.Sprintf(`export SWSV_URL=%s
export SWSV_TOKEN=%s
export SWSV_NS=%s
printf 'Authorization: Bearer %%s\n' "$SWSV_TOKEN" | curl -sS -X POST "$SWSV_URL/v1/fetch" -H @- -H 'Content-Type: application/json' -d '{"secret":"vault:%s/<secret-id>","method":"GET","url":"https://api.example.com/"}'`, base, token, project, project)
	mcpExample := fmt.Sprintf(`{
  "mcpServers": {
    "sws-vault": {
      "type": "http",
      "url": "%s/mcp",
      "headers": { "Authorization": "Bearer ${SWSV_TOKEN}" }
    }
  }
}`, base)
	resultTitle := "已接入"
	if projectExists != 0 {
		resultTitle = "追加接入"
	}
	cidrNote := ""
	if cidrList != "" {
		cidrNote = strings.Join(cidrs, ", ")
	}
	w.Header().Set("Cache-Control", "no-store")
	render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>项目配置</title><h1>{{.Project}} {{.Title}}</h1>{{if .BaseURLMissing}}<div class="note warn">PUBLIC_BASE_URL 未配置，请把占位符替换为面板地址。</div>{{end}}<div class="note danger">客户端令牌只显示这一次，请立即复制并妥善保存。</div><section class="secret"><header>环境变量配置<button type="button" class="btn small secondary copy">复制</button></header><pre>{{.Env}}</pre></section>{{if .AllowResolve}}<section class="secret"><header>命令调用示例<button type="button" class="btn small secondary copy">复制</button></header><pre>{{.Run}}</pre></section><p>该命令将密钥值注入子进程环境变量 SWSV_SECRET。</p><section class="secret"><header>Git 凭据助手配置<button type="button" class="btn small secondary copy">复制</button></header><pre>{{.Git}}</pre></section><p class="hint">此令牌可以取出明文，不要交给 AI。</p>{{else}}<section class="secret"><header>代发调用示例<button type="button" class="btn small secondary copy">复制</button></header><pre>{{.Fetch}}</pre></section><p class="hint">令牌只放在环境变量或 -H @- 里，不会出现在命令行参数中。</p><section class="secret"><header>MCP 配置示例<button type="button" class="btn small secondary copy">复制</button></header><pre>{{.MCP}}</pre></section><p class="hint">此令牌只能代发请求，不能取出明文。</p>{{end}}{{if .CIDRs}}<p class="hint">限制来源 IP：{{.CIDRs}}</p>{{end}}<p class="hint">本次关联密钥数：{{.Count}}</p><p class="hint">使用范围：本次从未关联区选中的密钥仅授权给本次新建的客户端；原已属于此项目的密钥保留原有范围，并将本次客户端加入允许列表。原本未限制客户端的项目密钥仍可由项目内所有具备权限的客户端使用。</p><div class="bar"><a class="btn secondary" href="/admin/">返回首页</a></div>`, map[string]any{"Project": project, "Title": resultTitle, "Env": env, "Run": runExample, "Git": gitExample, "Fetch": fetchExample, "MCP": mcpExample, "Count": len(selected), "BaseURLMissing": baseURLMissing, "AllowResolve": allowResolve, "CIDRs": cidrNote})
}

// normalizeCIDRs 规范化逗号分隔的 IP / CIDR：单个 IPv4 补 /32，单个 IPv6 补 /128，CIDR 归一为网络地址。
// 任一取值非法即返回错误；调用方必须在创建任何记录之前拒绝请求，避免留下半成品。
func normalizeCIDRs(raw string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		v := strings.TrimSpace(part)
		if v == "" {
			continue
		}
		if ip := net.ParseIP(v); ip != nil {
			if ip.To4() != nil {
				out = append(out, ip.String()+"/32")
			} else {
				out = append(out, ip.String()+"/128")
			}
			continue
		}
		_, network, err := net.ParseCIDR(v)
		if err != nil {
			return nil, fmt.Errorf("invalid source address %q", v)
		}
		out = append(out, network.String())
	}
	return out, nil
}
