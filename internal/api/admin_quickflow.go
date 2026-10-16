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

// adminNewSecret 渲染并处理新建密钥（C，设计稿 ②③）。
// 使用范围由平台模板自动生成，表单上只出现模板参数（Gitea 地址 / 其他平台的域名与 Header）。
func (s *Server) adminNewSecret(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		preselected := strings.TrimSpace(r.URL.Query().Get("project"))
		fromProject := r.URL.Query().Get("from") == "project"
		rows, e := s.S.DB.Query(`SELECT name FROM namespaces WHERE name<>? AND substr(name,1,1)<>'_' ORDER BY name`, unassignedNS)
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
		render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>新建密钥</title><h1>新建密钥</h1><p class="lead">粘贴后立即加密保存，密钥值不会再次显示。</p><form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}">{{if .FromProject}}<input type="hidden" name="from" value="project">{{end}}<fieldset class="choices"><legend>平台</legend><label class="choice"><input type="radio" name="provider" value="cloudflare-token" checked><span><i class="brand-cloudflare">CF</i><b>Cloudflare</b></span></label><label class="choice"><input type="radio" name="provider" value="github-pat"><span><i class="brand-github">GH</i><b>GitHub</b></span></label><label class="choice"><input type="radio" name="provider" value="gitea-token"><span><i class="brand-gitea">Gt</i><b>Gitea</b></span></label><label class="choice"><input type="radio" name="provider" value="generic"><span><i class="brand-generic">··</i><b>其他</b></span></label></fieldset><label>名称 <input name="label" required maxlength="128" autocomplete="off"></label><label>密钥值 <input type="password" name="value" autocomplete="off" required placeholder="粘贴到这里，保存后不再显示"></label><label class="gitea-only">Gitea 地址（选择 Gitea 时必填，例如 https://git.example.com） <input name="gitea_address" autocomplete="url"><small class="hint">只会发往这个域名。</small></label><label class="gitea-only"><input type="checkbox" name="allow_http">允许 HTTP（仅在明确需要时启用）</label><label class="generic-only">允许发往的域名（选择其他平台时必填，逗号分隔） <input name="hosts" autocomplete="off"></label><label class="generic-only">Header 模板 JSON <input name="headers" autocomplete="off" placeholder="{&quot;Authorization&quot;:&quot;Bearer {v}&quot;}"></label><label>放进项目（可选） <select name="project"><option value="">先放在「未归入项目」</option>{{range .Projects}}<option value="{{.}}"{{if eq . $.SelectedProject}} selected{{end}}>{{.}}</option>{{end}}</select><small class="hint">不选就先放在「未归入项目」，任何接入方都用不了。</small></label><div class="bar"><button class="btn block">保存</button></div></form>`, map[string]any{"CSRF": sess.csrf, "Projects": names, "SelectedProject": preselected, "FromProject": fromProject})
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
	fromProject := r.Form.Get("from") == "project"
	q := SecretRequest{NS: ns, Label: strings.TrimSpace(r.Form.Get("label")), Provider: providerName, Type: "token", Value: r.Form.Get("value"), Bindings: Binding{Hosts: hosts, AllowResolve: true, NoClientAccess: fromProject, AllowPrivate: r.Form.Get("allow_private") == "on", AllowHTTP: r.Form.Get("allow_http") == "on"}}
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
	// 成功页（③）：名称 · 平台 · 尾号、所在项目，加「给谁用 →」和「完成」两条路。
	projectName := "还没放进项目"
	useHref := "/admin/secrets/" + m.ID + "/project?next=clients"
	scopeNote := "该密钥还没放进项目，任何接入方都用不了；先「给谁用 →」把它放进一个项目。"
	if project != "" {
		projectName = project
		useHref = "/admin/projects/" + project + "/clients/new?secret=" + m.ID
		if fromProject {
			scopeNote = "该密钥尚未授权给任何接入方；「给谁用 →」给它发一张通行证。"
		} else {
			scopeNote = "该项目内所有具备 resolve 权限的客户端均可使用此密钥；也可以「给谁用 →」发一张专门的通行证。"
		}
	}
	if providerName == "gitea-token" {
		scopeNote = "允许发往域名：" + strings.Join(hosts, ", ") + "。" + scopeNote
	}
	render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>已保存</title><div class="hero"><span class="seal" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="m5 12 4 4L19 6" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg></span><h1>已保存</h1></div><p class="lead">{{.Label}} · {{.Provider}} · 尾号 {{.Tail}}<br>放在项目 {{.Project}}</p><p class="hint">{{.ScopeNote}}</p><p class="hint">密钥值不会再次显示。</p><div class="bar-actions"><a class="btn block" href="{{.UseHref}}">给谁用 →</a></div><p class="hint">生成一张通行证，让 AI 或脚本能代发请求。</p><div class="bar-actions"><a class="btn secondary block" href="/admin/secrets/{{.SecretID}}">完成</a></div>`, map[string]string{"Label": q.Label, "Provider": providerLabel(providerName), "Tail": secretTail(m.Preview), "Project": projectName, "ScopeNote": scopeNote, "UseHref": useHref, "SecretID": m.ID})
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
		providerNames := map[string]string{"cloudflare-token": "Cloudflare", "github-pat": "GitHub", "gitea-token": "Gitea", "generic": "其他"}
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
	// 项目内已有的空授权列表密钥先显式化，未勾选的密钥才不会对新客户端开放。
	if e = authorizeProjectSecrets(tx, project, clientID, selected, allowResolve); e != nil {
		adminErrOut(w, 500, "could not authorize selected secrets")
		return
	}
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
	resultTitle := "已接入"
	if projectExists != 0 {
		resultTitle = "追加接入"
	}
	s.renderPassport(w, passportView{
		Project:      project,
		Title:        resultTitle,
		Token:        token,
		AllowResolve: allowResolve,
		CIDRs:        strings.Join(cidrs, ", "),
		Count:        len(selected),
		ScopeNote:    "本次从未关联区选中的密钥仅授权给本次新建的客户端；原已属于此项目的密钥保留原有范围，并将本次客户端加入允许列表。原本未限制客户端的项目密钥仍可由项目内所有具备权限的客户端使用。",
		BackHref:     "/admin/",
		BackLabel:    "返回首页",
	})
}

type passportView struct {
	Project      string
	Title        string
	Token        string
	AllowResolve bool
	CIDRs        string
	Count        int
	ScopeNote    string
	BackHref     string
	BackLabel    string
}

// renderPassport 渲染一次性的通行证结果页；快捷「接入项目」与项目页共用同一套渲染。
func (s *Server) renderPassport(w http.ResponseWriter, v passportView) {
	base := strings.TrimRight(s.C.PublicBaseURL, "/")
	baseURLMissing := base == ""
	if baseURLMissing {
		base = "<SWSV_URL>"
	}
	env := fmt.Sprintf("SWSV_URL=%s\nSWSV_TOKEN=%s\nSWSV_NS=%s", base, v.Token, v.Project)
	runExample := fmt.Sprintf("SWSV_URL=%s SWSV_TOKEN=%s SWSV_NS=%s swsvault run --secret vault:%s/<secret-id> -- <command>", base, v.Token, v.Project, v.Project)
	gitExample := fmt.Sprintf("git config --global credential.helper '!SWSV_URL=%s SWSV_TOKEN=%s SWSV_NS=%s swsvault git-credential'", base, v.Token, v.Project)
	// 代发示例用 read -rs 交互读入令牌：令牌本体不出现在页面和 shell 历史里。
	fetchExample := fmt.Sprintf(`read -rs SWSV_TOKEN
export SWSV_URL=%s
export SWSV_NS=%s
printf 'Authorization: Bearer %%s\n' "$SWSV_TOKEN" | curl -sS -X POST "$SWSV_URL/v1/fetch" -H @- -H 'Content-Type: application/json' -d '{"secret":"vault:%s/<secret-id>","method":"GET","url":"https://api.example.com/"}'`, base, v.Project, v.Project)
	mcpExample := fmt.Sprintf(`{
  "mcpServers": {
    "sws-vault": {
      "type": "http",
      "url": "%s/mcp",
      "headers": { "Authorization": "Bearer ${SWSV_TOKEN}" }
    }
  }
}`, base)
	w.Header().Set("Cache-Control", "no-store")
	render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>项目配置</title><h1>{{.Project}} {{.Title}}</h1>{{if .BaseURLMissing}}<div class="note warn">PUBLIC_BASE_URL 未配置，请把占位符替换为面板地址。</div>{{end}}<div class="note danger">客户端令牌只显示这一次，请立即复制并妥善保存。</div><section class="secret"><header>环境变量配置<button type="button" class="btn small secondary copy">复制</button></header><pre>{{.Env}}</pre></section>{{if .AllowResolve}}<section class="secret"><header>命令调用示例<button type="button" class="btn small secondary copy">复制</button></header><pre>{{.Run}}</pre></section><p>该命令将密钥值注入子进程环境变量 SWSV_SECRET。</p><section class="secret"><header>Git 凭据助手配置<button type="button" class="btn small secondary copy">复制</button></header><pre>{{.Git}}</pre></section><p class="hint">此令牌可以取出明文，不要交给 AI。</p>{{else}}<section class="secret"><header>代发调用示例<button type="button" class="btn small secondary copy">复制</button></header><pre>{{.Fetch}}</pre></section><p class="hint">令牌只放在环境变量或 -H @- 里，不会出现在命令行参数中，也不会进 shell 历史。</p><section class="secret"><header>MCP 配置示例<button type="button" class="btn small secondary copy">复制</button></header><pre>{{.MCP}}</pre></section><p class="hint">MCP 客户端是否展开 ${SWSV_TOKEN} 由它自己决定；不展开的客户端要把令牌填进它自己的密钥配置，不要写进会提交到仓库的文件。</p><p class="hint">此令牌只能代发请求，不能取出明文。</p>{{end}}<p class="hint">来源 IP：{{if .CIDRs}}{{.CIDRs}}{{else}}不限{{end}}</p><p class="hint">本次关联密钥数：{{.Count}}</p>{{if .ScopeNote}}<p class="hint">使用范围：{{.ScopeNote}}</p>{{end}}<div class="bar"><a class="btn secondary" href="{{.BackHref}}">{{.BackLabel}}</a></div>`, map[string]any{"Project": v.Project, "Title": v.Title, "Env": env, "Run": runExample, "Git": gitExample, "Fetch": fetchExample, "MCP": mcpExample, "Count": v.Count, "BaseURLMissing": baseURLMissing, "AllowResolve": v.AllowResolve, "CIDRs": v.CIDRs, "ScopeNote": v.ScopeNote, "BackHref": v.BackHref, "BackLabel": v.BackLabel})
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
