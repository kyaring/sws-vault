package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
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
	rows, e := s.S.DB.Query(`SELECT n.name,(SELECT count(*) FROM secrets x WHERE x.ns=n.name AND x.status='active'),(SELECT count(*) FROM clients c WHERE c.ns=n.name AND c.disabled=0) FROM namespaces n WHERE n.name<>? ORDER BY n.name`, unassignedNS)
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	defer rows.Close()
	type project struct {
		Name             string
		Secrets, Clients int
	}
	var projects []project
	for rows.Next() {
		var p project
		if rows.Scan(&p.Name, &p.Secrets, &p.Clients) == nil {
			projects = append(projects, p)
		}
	}
	var unassigned int
	_ = s.S.DB.QueryRow(`SELECT count(*) FROM secrets WHERE ns=? AND status='active'`, unassignedNS).Scan(&unassigned)
	render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>SWS Vault</title><link rel="stylesheet" href="/admin/assets/admin.css"><h1>SWS Vault</h1><nav><a class="primary" href="/admin/secrets/new">新建</a> <a class="primary" href="/admin/quick/project">接入项目</a></nav><h2>项目</h2>{{if .Projects}}<table><tr><th>项目</th><th>密钥数</th><th>客户端数</th></tr>{{range .Projects}}<tr><td>{{.Name}}</td><td>{{.Secrets}}</td><td>{{.Clients}}</td></tr>{{end}}</table>{{else}}<p>还没有项目。选择「接入项目」开始。</p>{{end}}<p><a href="/admin/advanced/secrets">高级 · 密钥</a> · <a href="/admin/advanced">更多高级功能</a></p><p><a href="/admin/advanced/secrets?ns=_unassigned">未关联密钥（{{.Unassigned}}）</a></p><form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>退出</button></form>`, map[string]any{"CSRF": sess.csrf, "Projects": projects, "Unassigned": unassigned})
}

func (s *Server) adminAdvanced(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>高级功能</title><h1>高级</h1><ul><li><a href="/admin/advanced/secrets">密钥列表</a></li><li><a href="/admin/namespaces">项目管理</a></li><li><a href="/admin/clients">客户端</a></li><li><a href="/admin/audit">审计事件</a></li><li><a href="/admin/intents/new">一次性录入链接</a></li></ul><form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>退出</button></form><a href="/admin/">返回首页</a>`, map[string]string{"CSRF": sess.csrf})
}

func (s *Server) adminNewSecret(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		rows, e := s.S.DB.Query(`SELECT name FROM namespaces WHERE name<>? ORDER BY name`, unassignedNS)
		if e != nil {
			errOut(w, 500, "internal error")
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
		render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>新建密钥</title><link rel="stylesheet" href="/admin/assets/admin.css"><h1>新建</h1><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>平台 <select name="provider"><option value="cloudflare-token">Cloudflare API Token</option><option value="github-pat">GitHub</option><option value="gitea-token">Gitea</option><option value="generic">通用</option></select></label><label>名称 <input name="label" required maxlength="128"></label><label>密钥值 <input type="password" name="value" autocomplete="off" required></label><label>关联项目（可选） <select name="project"><option value="">暂不关联</option>{{range .Projects}}<option value="{{.}}">{{.}}</option>{{end}}</select></label><label class="generic-only">允许发往的域名（仅通用平台，逗号分隔） <input name="hosts" autocomplete="off"></label><label class="generic-only">Header 模板 JSON <input name="headers" autocomplete="off" placeholder="{&quot;Authorization&quot;:&quot;Bearer {v}&quot;}"></label><button>保存</button></form><p><a href="/admin/">取消</a></p>`, map[string]any{"CSRF": sess.csrf, "Projects": names})
		return
	}
	if r.Method != http.MethodPost {
		errOut(w, 405, "method not allowed")
		return
	}
	_ = r.ParseForm()
	providerName := r.Form.Get("provider")
	project := strings.TrimSpace(r.Form.Get("project"))
	ns := unassignedNS
	if project != "" {
		if !projectNamePattern.MatchString(project) {
			errOut(w, 400, "invalid project name")
			return
		}
		var n int
		if e := s.S.DB.QueryRow(`SELECT count(*) FROM namespaces WHERE name=?`, project).Scan(&n); e != nil || n == 0 {
			errOut(w, 400, "project not found")
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
		hosts = []string{"gitea.com"}
	case "generic":
		for _, h := range strings.Split(r.Form.Get("hosts"), ",") {
			if h = strings.TrimSpace(h); h != "" {
				hosts = append(hosts, h)
			}
		}
	default:
		errOut(w, 400, "invalid provider")
		return
	}
	if providerName == "generic" && len(hosts) == 0 {
		errOut(w, 400, "allowed domain required for generic platform")
		return
	}
	q := SecretRequest{NS: ns, Label: strings.TrimSpace(r.Form.Get("label")), Provider: providerName, Type: "token", Value: r.Form.Get("value"), Bindings: Binding{Hosts: hosts, AllowResolve: true, AllowPrivate: r.Form.Get("allow_private") == "on", AllowHTTP: r.Form.Get("allow_http") == "on"}}
	if providerName == "generic" {
		q.Bindings.Headers = map[string]string{"Authorization": "Bearer {v}"}
		if raw := strings.TrimSpace(r.Form.Get("headers")); raw != "" {
			if json.Unmarshal([]byte(raw), &q.Bindings.Headers) != nil {
				errOut(w, 400, "invalid header templates")
				return
			}
		}
	}
	if r.Form.Get("verify") == "on" {
		if e := s.verifySecret(q, r.Form.Get("base_url")); e != nil {
			errOut(w, 400, e.Error())
			return
		}
	}
	m, e := s.save(q, false, "")
	if e != nil {
		errOut(w, 400, "could not save secret")
		return
	}
	s.audit("admin", ns, "write", m.ID, "", "ok", s.sourceIP(r))
	slog.Info("admin secret stored", "namespace", ns, "secret_id", m.ID, "provider", providerName)
	w.Header().Set("Cache-Control", "no-store")
	association := "未关联"
	scopeNote := "该密钥位于未关联区，项目客户端不能读取；请通过「接入项目」选择目标客户端。"
	if project != "" {
		association = project
		scopeNote = "该项目内所有具备 resolve 权限的客户端均可使用此密钥。"
	}
	providerLabel := map[string]string{"cloudflare-token": "Cloudflare", "github-pat": "GitHub", "gitea-token": "Gitea", "generic": "通用"}[providerName]
	render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>已保存</title><h1>已保存</h1><dl><dt>名称</dt><dd>{{.Label}}</dd><dt>平台</dt><dd>{{.Provider}}</dd><dt>关联状态</dt><dd>{{.Association}}</dd></dl><p>使用范围：{{.ScopeNote}}</p><p>密钥值不会再次显示。</p><a href="/admin/">返回首页</a> · <a href="/admin/quick/project">接入项目</a>`, map[string]string{"Label": q.Label, "Provider": providerLabel, "Association": association, "ScopeNote": scopeNote})
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
			render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><link rel="stylesheet" href="/admin/assets/admin.css"><title>接入项目</title><h1>接入项目</h1><p>先填写项目名，再选择要提供给项目的密钥。</p><form method="get" action="/admin/quick/project"><label>项目名（小写字母、数字、连字符） <input name="project" pattern="[a-z0-9][a-z0-9-]{0,63}" required></label><label>客户端名称 <input name="client" value="default" pattern="[A-Za-z0-9._-]{1,64}" required></label><button>下一步：选择密钥</button></form><a href="/admin/">取消</a>`, nil)
			return
		}
		if !projectNamePattern.MatchString(project) || !namePattern.MatchString(client) {
			errOut(w, 400, "invalid project or client name")
			return
		}
		rows, e := s.S.DB.Query(`SELECT id,label,ns FROM secrets WHERE status='active' AND (ns=? OR ns=?) ORDER BY label`, unassignedNS, project)
		if e != nil {
			errOut(w, 500, "internal error")
			return
		}
		defer rows.Close()
		type item struct{ ID, Label, Project string }
		var items []item
		for rows.Next() {
			var x item
			if rows.Scan(&x.ID, &x.Label, &x.Project) == nil {
				items = append(items, x)
			}
		}
		render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><link rel="stylesheet" href="/admin/assets/admin.css"><title>接入项目</title><h1>接入项目：{{.Project}}</h1><p>选择未关联密钥或已经属于此项目的密钥。提交后会创建一个新的客户端令牌。</p><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="project" value="{{.Project}}"><input type="hidden" name="client" value="{{.Client}}"><fieldset><legend>可选密钥</legend>{{range .Items}}<label><input type="checkbox" name="secret" value="{{.ID}}">{{.Label}} — {{if eq .Project "_unassigned"}}未关联{{else}}{{.Project}}{{end}}</label>{{else}}<p>暂无可选密钥。</p>{{end}}</fieldset><button>生成项目配置</button></form><a href="/admin/quick/project">返回上一步</a> · <a href="/admin/">取消</a>`, map[string]any{"CSRF": sess.csrf, "Items": items, "Project": project, "Client": client})
		return
	}
	if r.Method != http.MethodPost {
		errOut(w, 405, "method not allowed")
		return
	}
	_ = r.ParseForm()
	project := strings.TrimSpace(r.Form.Get("project"))
	clientName := strings.TrimSpace(r.Form.Get("client"))
	if !projectNamePattern.MatchString(project) || !namePattern.MatchString(clientName) {
		errOut(w, 400, "invalid project or client name")
		return
	}
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		errOut(w, 500, "internal error")
		return
	}
	token := "swsv_" + base64.RawURLEncoding.EncodeToString(raw)
	for i := range raw {
		raw[i] = 0
	}
	sum := sha256.Sum256([]byte(token))
	projectID, e := randomID()
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	clientID, e := randomID()
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	var projectExists int
	_ = s.S.DB.QueryRow(`SELECT count(*) FROM namespaces WHERE name=?`, project).Scan(&projectExists)
	tx, e := s.S.DB.Begin()
	if e != nil {
		errOut(w, 500, "internal error")
		return
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339)
	_, e = tx.Exec(`INSERT INTO namespaces(id,name,created_at) VALUES(?,?,?) ON CONFLICT(name) DO NOTHING`, projectID, project, now)
	if e != nil {
		errOut(w, 500, "could not create project")
		return
	}
	_, e = tx.Exec(`INSERT INTO clients(id,ns,name,token_hash,scopes,cidrs,expires_at,disabled,created_at) VALUES(?,?,?,?,?,'','',0,?)`, clientID, project, clientName, sum[:], "secrets:list,resolve,fetch", now)
	if e != nil {
		errOut(w, 500, "could not create client")
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
			errOut(w, 400, "selected secret unavailable")
			return
		}
		var bd Binding
		if json.Unmarshal([]byte(b), &bd) != nil {
			errOut(w, 500, "invalid stored policy")
			return
		}
		dek, e := s.unwrapDEK(oldNS, sid, uint32(version), wrapped)
		if e != nil {
			errOut(w, 500, "could not move selected secret")
			return
		}
		value, e := vaultcrypto.Open(dek, ct, vaultcrypto.SecretAAD(oldNS, sid, typ, uint32(version)))
		if e != nil {
			wipe(dek)
			errOut(w, 500, "could not move selected secret")
			return
		}
		newCT, e := vaultcrypto.Seal(dek, value, vaultcrypto.SecretAAD(project, sid, typ, uint32(version)))
		if e != nil {
			wipe(dek)
			wipe(value)
			errOut(w, 500, "could not move selected secret")
			return
		}
		newWrapped, e := s.wrapDEK(project, sid, uint32(version), dek)
		wipe(dek)
		wipe(value)
		if e != nil {
			errOut(w, 500, "could not move selected secret")
			return
		}
		bd.AllowResolve = true
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
			errOut(w, 500, "could not move selected secret")
			return
		}
	}
	if e = tx.Commit(); e != nil {
		errOut(w, 500, "could not commit project")
		return
	}
	s.audit("admin", project, "project-client-create", "", "", "ok", s.sourceIP(r))
	for _, sid := range selected {
		s.audit("admin", project, "secret-associate", sid, "", "ok", s.sourceIP(r))
	}
	base := strings.TrimRight(s.C.PublicBaseURL, "/")
	if base == "" {
		base = "http://192.168.20.132:9531"
	}
	env := fmt.Sprintf("SWSV_URL=%s\nSWSV_TOKEN=%s\nSWSV_NS=%s", base, token, project)
	runExample := fmt.Sprintf("SWSV_URL=%s SWSV_TOKEN=%s SWSV_NS=%s swsvault run --secret vault:%s/<secret-id> -- <command>", base, token, project, project)
	gitExample := fmt.Sprintf("git config --global credential.helper '!SWSV_URL=%s SWSV_TOKEN=%s SWSV_NS=%s swsvault git-credential'", base, token, project)
	resultTitle := "已接入"
	if projectExists != 0 {
		resultTitle = "追加接入"
	}
	w.Header().Set("Cache-Control", "no-store")
	render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>项目配置</title><h1>{{.Project}} {{.Title}}</h1><p>客户端令牌只显示这一次，请立即复制并妥善保存。</p><p>使用范围：本次从未关联区选中的密钥仅授权给本次新建的客户端；原已属于此项目的密钥保留原有范围，并将本次客户端加入允许列表。原本未限制客户端的项目密钥仍可由项目内所有具备权限的客户端使用。</p><label>环境变量配置<textarea readonly rows="3">{{.Env}}</textarea></label><label>命令调用示例<textarea readonly rows="2">{{.Run}}</textarea></label><p>该命令将密钥值注入子进程环境变量 SWSV_SECRET。</p><label>Git 凭据助手配置<textarea readonly rows="2">{{.Git}}</textarea></label><p>本次关联密钥数：{{.Count}}</p><a href="/admin/">返回首页</a>`, map[string]any{"Project": project, "Title": resultTitle, "Env": env, "Run": runExample, "Git": gitExample, "Count": len(selected)})
}
