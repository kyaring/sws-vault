package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// 密钥标签 /admin/secrets 与密钥详情 /admin/secrets/{id}（SV-20261016-07 B、D）。
// 面板只显示名称、平台、尾号（沿用既有的 preview）和指纹，永远不显示密钥值。

const secretKeyIconWarn = `<span class="dot warn" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="8" cy="15" r="4" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="m11 12 8-8 2 2-2 2 2 2-3 3-2-2-3 3" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg></span>`

const secretKeyIcon = `<span class="dot" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="8" cy="15" r="4" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="m11 12 8-8 2 2-2 2 2 2-3 3-2-2-3 3" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg></span>`

// bindingsFormTemplate 是「使用范围」编辑表单的共用片段：
// /admin/secrets/{id}/bindings 单独打开时用它，密钥详情页的「请求限制」折叠区也用它（D）。
const bindingsFormTemplate = `<form method="post" action="{{.FormAction}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>用户名<input name="username" value="{{.Username}}"></label><label>允许接入方 IDs<input name="allowed_clients" value="{{.AllowedClients}}"><small class="hint">{{if .NoClientAccess}}当前尚未授权给任何接入方；留空保存会保持这个状态，填入接入方 ID 才放行。{{else}}留空表示项目内所有接入方都能用。{{end}}</small></label><label>允许主机<input name="hosts" value="{{.Hosts}}"></label><label>Header 模板 JSON<input name="headers" value="{{.Headers}}"></label><label>允许解析<input type="checkbox" name="allow_resolve" {{if .AllowResolve}}checked{{end}}></label><label>允许私网<input type="checkbox" name="allow_private" {{if .AllowPrivate}}checked{{end}}></label><label>允许 HTTP<input type="checkbox" name="allow_http" {{if .AllowHTTP}}checked{{end}}></label><button class="btn block">保存</button></form>`

func containsID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// secretTail 取尾号：沿用既有 preview（普通平台是「••••」+ 末四位），只去掉掩码前缀。
func secretTail(preview string) string {
	return strings.TrimPrefix(preview, "••••")
}

// secretUseLabel 生成副标题里的使用状态：接入方数 / 已停用 / 还没人能用。
func secretUseLabel(status, ns string, bd Binding, projectClients int) string {
	if status != "active" {
		return "已停用"
	}
	if ns == unassignedNS || bd.NoClientAccess {
		return "还没人能用"
	}
	if len(bd.AllowedClients) > 0 {
		return fmt.Sprintf("%d 个接入方", len(bd.AllowedClients))
	}
	if projectClients == 0 {
		return "还没人能用"
	}
	return fmt.Sprintf("%d 个接入方", projectClients)
}

type secretKeyView struct {
	ID, Label, Provider, Tail, Subtitle string
}

type secretGroupView struct {
	Name string
	Keys []secretKeyView
}

func (g secretGroupView) Count() int { return len(g.Keys) }

// adminSecrets 渲染密钥标签：按项目分组列出全部密钥，未归入项目组置顶。
func (s *Server) adminSecrets(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		adminErrOut(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	clients := map[string]int{}
	crows, e := s.S.DB.Query(`SELECT ns,count(*) FROM clients WHERE disabled=0 GROUP BY ns`)
	if e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	for crows.Next() {
		var ns string
		var n int
		if crows.Scan(&ns, &n) == nil {
			clients[ns] = n
		}
	}
	crows.Close()
	rows, e := s.S.DB.Query(`SELECT id,ns,label,provider,preview,status,bindings FROM secrets ORDER BY label`)
	if e != nil {
		adminErrOut(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()
	byNS := map[string][]secretKeyView{}
	total := 0
	for rows.Next() {
		var id, ns, label, provider, preview, status, raw string
		if rows.Scan(&id, &ns, &label, &provider, &preview, &status, &raw) != nil {
			continue
		}
		total++
		shown := providerLabel(provider)
		if query != "" && !strings.Contains(strings.ToLower(label), strings.ToLower(query)) && !strings.Contains(strings.ToLower(shown), strings.ToLower(query)) {
			continue
		}
		var bd Binding
		_ = json.Unmarshal([]byte(raw), &bd)
		byNS[ns] = append(byNS[ns], secretKeyView{ID: id, Label: label, Provider: shown, Tail: secretTail(preview), Subtitle: secretUseLabel(status, ns, bd, clients[ns])})
	}
	var unassigned *secretGroupView
	var names []string
	for ns, keys := range byNS {
		sort.Slice(keys, func(i, j int) bool { return keys[i].Label < keys[j].Label })
		if strings.HasPrefix(ns, "_") {
			// 未归入项目的密钥（含历史遗留的保留前缀）统一并到置顶组。
			if unassigned == nil {
				unassigned = &secretGroupView{Name: "未归入项目"}
			}
			unassigned.Keys = append(unassigned.Keys, keys...)
			continue
		}
		names = append(names, ns)
	}
	if unassigned != nil {
		sort.Slice(unassigned.Keys, func(i, j int) bool { return unassigned.Keys[i].Label < unassigned.Keys[j].Label })
	}
	sort.Strings(names)
	groups := make([]secretGroupView, 0, len(names))
	for _, ns := range names {
		groups = append(groups, secretGroupView{Name: ns, Keys: byNS[ns]})
	}
	render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>密钥</title><h1>密钥</h1><p class="lead">值永远不会显示在面板上。</p><p class="page-action"><a href="/admin/secrets/new" aria-label="新建密钥">＋</a></p>{{if .ShowSearch}}<form method="get" action="/admin/secrets"><label>搜索<input name="q" value="{{.Query}}" autocomplete="off" placeholder="按名称或平台过滤"></label><button class="btn secondary">搜索</button></form>{{end}}{{with .Unassigned}}<h2>未归入项目 · {{.Count}}</h2><div class="group">{{range .Keys}}<a class="row" href="/admin/secrets/{{.ID}}">`+secretKeyIconWarn+`<span class="t">{{.Label}}<small>{{.Provider}} · 尾号 {{.Tail}} · {{.Subtitle}}</small></span></a>{{end}}</div>{{end}}{{range .Groups}}<h2>{{.Name}}</h2><div class="group">{{range .Keys}}<a class="row" href="/admin/secrets/{{.ID}}">`+secretKeyIcon+`<span class="t">{{.Label}}<small>{{.Provider}} · 尾号 {{.Tail}} · {{.Subtitle}}</small></span></a>{{end}}</div>{{end}}{{if not .HasKeys}}<p class="hint">{{if .Query}}没有匹配的密钥。{{else}}还没有密钥。选择右上角的「＋」新建一个。{{end}}</p>{{end}}`, map[string]any{"CSRF": sess.csrf, "Query": query, "ShowSearch": total > 20, "Unassigned": unassigned, "Groups": groups, "HasKeys": unassigned != nil || len(groups) > 0})
}

// adminSecretDetail 渲染密钥详情（D）：项目、最近使用、谁在用、请求限制、轮换 / 停用。
func (s *Server) adminSecretDetail(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		adminErrOut(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/admin/secrets/")
	if !namePattern.MatchString(id) {
		adminErrOut(w, http.StatusNotFound, "not found")
		return
	}
	var ns, label, provider, preview, fingerprint, status, raw, lastUsed string
	if e := s.S.DB.QueryRow(`SELECT ns,label,provider,preview,fingerprint,status,bindings,last_used_at FROM secrets WHERE id=?`, id).Scan(&ns, &label, &provider, &preview, &fingerprint, &status, &raw, &lastUsed); e != nil {
		adminErrOut(w, http.StatusNotFound, "not found")
		return
	}
	var bd Binding
	if json.Unmarshal([]byte(raw), &bd) != nil {
		adminErrOut(w, http.StatusInternalServerError, "invalid stored policy")
		return
	}
	if len(fingerprint) > 8 {
		fingerprint = fingerprint[:8]
	}
	// 最近使用：优先用审计里的最后一次代发，退回 last_used_at。
	recent := ""
	var at, actor string
	if e := s.S.DB.QueryRow(`SELECT at,actor FROM audit WHERE secret_id=? AND action='fetch' ORDER BY id DESC LIMIT 1`, id).Scan(&at, &actor); e == nil {
		var name string
		_ = s.S.DB.QueryRow(`SELECT name FROM clients WHERE id=?`, actor).Scan(&name)
		if name == "" {
			name = actor
		}
		recent = relativeUseTime(at) + " · " + name
	} else if lastUsed != "" {
		recent = relativeUseTime(lastUsed)
	}
	if recent == "" {
		recent = "从未使用"
	}
	// 谁在用：所属项目内的全部接入方，开 = 该接入方在此密钥的授权里。
	type clientView struct {
		ID, Name, Permission string
		Allowed, Disabled    bool
	}
	var clientList []clientView
	project := ns
	if ns == unassignedNS {
		project = ""
	}
	if project != "" {
		crows, e := s.S.DB.Query(`SELECT id,name,scopes,disabled FROM clients WHERE ns=? ORDER BY created_at`, project)
		if e != nil {
			adminErrOut(w, http.StatusInternalServerError, "internal error")
			return
		}
		for crows.Next() {
			var v clientView
			var scopes string
			var disabled int
			if crows.Scan(&v.ID, &v.Name, &scopes, &disabled) == nil {
				v.Permission = clientPermission(scopes)
				v.Disabled = disabled != 0
				switch {
				case bd.NoClientAccess:
					v.Allowed = false
				case len(bd.AllowedClients) > 0:
					v.Allowed = containsID(bd.AllowedClients, v.ID)
				default:
					v.Allowed = !v.Disabled
				}
				clientList = append(clientList, v)
			}
		}
		crows.Close()
	}
	headers, _ := json.Marshal(bd.Headers)
	firstHost := ""
	if len(bd.Hosts) > 0 {
		firstHost = bd.Hosts[0]
	}
	projectName := project
	detail := `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>密钥详情</title><h1>{{.Label}}</h1><p class="lead">{{.Provider}} · 尾号 {{.Tail}}{{if .Fingerprint}} · 指纹 {{.Fingerprint}}{{end}}{{if .Disabled}} · 已停用{{end}}</p><div class="group"><span class="row"><span class="t">项目<small>{{if .Project}}{{.Project}}{{else}}未归入项目{{end}}</small></span></span><span class="row"><span class="t">最近使用<small>{{.Recent}}</small></span></span></div><h2>谁在用</h2>`
	if projectName == "" {
		detail += `<p class="hint">这个密钥还没有归入项目，任何接入方都用不了。</p>`
	} else if len(clientList) == 0 {
		detail += `<p class="hint">这个项目还没有接入方。</p>`
	} else {
		detail += `<form method="post" action="/admin/secrets/` + id + `/clients"><input type="hidden" name="csrf" value="{{.CSRF}}"><div class="group">{{range .Clients}}<label class="check"><input type="checkbox" name="client" value="{{.ID}}"{{if .Allowed}} checked{{end}}><span class="t">{{.Name}}<small>{{.Permission}}{{if .Disabled}} · 已停用{{end}}</small></span></label>{{end}}</div><button class="btn block">保存</button></form>`
	}
	detail += `<h2>请求限制</h2><details><summary>展开修改<span class="summary-value">{{.FirstHost}} ›</span></summary>` + bindingsFormTemplate + `</details><p class="hint">平台模板已自动填好，一般不用改。</p>`
	if status == "active" {
		detail += `<div class="bar-actions"><a class="btn secondary block" href="/admin/secrets/` + id + `/rotate">轮换</a></div><form method="post" action="/admin/secrets/` + id + `/disable"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="btn danger block">停用</button></form>`
	}
	detail += `</html>`
	render(w, detail, map[string]any{
		"CSRF": sess.csrf, "Label": label, "Provider": providerLabel(provider), "Tail": secretTail(preview),
		"Fingerprint": fingerprint, "Disabled": status != "active", "Project": projectName, "Recent": recent,
		"Clients": clientList, "FirstHost": firstHost, "FormAction": "/admin/secrets/" + id + "/bindings",
		"Username": mask(bd.Username), "Hosts": strings.Join(bd.Hosts, ","), "Headers": string(headers),
		"AllowedClients": strings.Join(bd.AllowedClients, ","), "AllowResolve": bd.AllowResolve,
		"AllowPrivate": bd.AllowPrivate, "AllowHTTP": bd.AllowHTTP, "NoClientAccess": bd.NoClientAccess,
	})
}
