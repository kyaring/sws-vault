package api

import (
	"html/template"
	"regexp"
	"strings"
)

// 导航骨架（SV-20261016-07 A1）：面板所有页面的外壳在这里统一生成，页面正文只管内容。
//
//	tab  —— 列表 / 详情 / 设置页：顶栏 + 底部三个标签，当前标签带 aria-current="page"。
//	form —— 新建 / 添加 / 编辑类表单页：顶栏只有「取消」+ 标题，不显示标签栏。
//	其它 —— 结果页、登录页、错误页等：沿用原来的顶栏，不显示标签栏。
const (
	panelKindTab  = "tab"
	panelKindForm = "form"
)

var (
	panelTitleRE = regexp.MustCompile(`(?is)<title>(.*?)</title>`)
	panelH1RE    = regexp.MustCompile(`(?is)<h1[^>]*>(.*?)</h1>`)
	// 密钥详情相关的表单页把提交地址写成 /admin/secrets/{id}/…，外壳据此还原上级详情页。
	panelSecretActionRE = regexp.MustCompile(`action="/admin/secrets/([A-Za-z0-9._-]+)/(?:rotate|bindings|clients)"`)
)

type panelTab struct {
	Key, Label, Href, Icon string
}

// panelTabs 是底部标签栏的三项。
func panelTabs() []panelTab {
	return []panelTab{
		{Key: "secrets", Label: "密钥", Href: "/admin/secrets", Icon: "◆"},
		{Key: "projects", Label: "项目", Href: "/admin/projects", Icon: "▦"},
		{Key: "audit", Label: "记录", Href: "/admin/audit", Icon: "☰"},
	}
}

func panelTitle(src string) string {
	if m := panelTitleRE.FindStringSubmatch(src); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// panelPageTitle 取页面标题：优先 <title>；老页面没有 <title> 时退回 <h1>（去掉标签后）。
func panelPageTitle(src string) string {
	if t := panelTitle(src); t != "" {
		return t
	}
	if m := panelH1RE.FindStringSubmatch(src); len(m) == 2 {
		return strings.TrimSpace(panelTagRE.ReplaceAllString(m[1], ""))
	}
	return ""
}

// panelPageKind 按页面 <title> 决定外壳形态，以及该高亮的标签 key（可能为空）。
func panelPageKind(src string) (string, string) {
	switch title := panelPageTitle(src); {
	case title == "所有密钥" || title == "密钥" || strings.HasPrefix(title, "密钥详情"):
		return panelKindTab, "secrets"
	case title == "项目" || strings.HasPrefix(title, "项目详情"):
		return panelKindTab, "projects"
	case title == "审计事件":
		return panelKindTab, "audit"
	case title == "设置":
		return panelKindTab, ""
	case title == "新建密钥" || title == "新建项目" || title == "添加接入方" || title == "从未关联移入" ||
		title == "创建一次性录入链接" || strings.HasPrefix(title, "修改使用范围") ||
		strings.HasPrefix(title, "轮换凭据") || title == "修改初始密码" || title == "设置双重验证":
		return panelKindForm, ""
	}
	return "", ""
}

// panelCancelHref 是表单页「取消」的去处：固定指向上级页面，不依赖浏览器历史。
func panelCancelHref(src string) string {
	switch title := panelPageTitle(src); {
	case title == "新建项目" || title == "添加接入方" || title == "从未关联移入" || title == "创建一次性录入链接":
		return "/admin/projects"
	case title == "新建密钥":
		return "/admin/secrets"
	case strings.HasPrefix(title, "修改使用范围") || strings.HasPrefix(title, "轮换凭据"):
		// 这两页都从密钥详情进入，取消回该密钥的详情页。
		if m := panelSecretActionRE.FindStringSubmatch(src); len(m) == 2 {
			return "/admin/secrets/" + m[1]
		}
		return "/admin/secrets"
	case title == "修改初始密码" || title == "设置双重验证":
		return "/admin/settings"
	}
	return "/admin/"
}

func panelTabBar(current string) string {
	var b strings.Builder
	b.WriteString(`<nav class="tabbar" aria-label="主导航">`)
	for _, item := range panelTabs() {
		b.WriteString(`<a class="tabitem" href="` + item.Href + `"`)
		if item.Key == current {
			b.WriteString(` aria-current="page"`)
		}
		b.WriteString(`><span class="tabicon" aria-hidden="true">` + item.Icon + `</span>` + item.Label + `</a>`)
	}
	b.WriteString(`</nav>`)
	return b.String()
}

// panelShell 返回页面外壳（<body> + 顶栏 + <main>）与收尾（</main> + 可选标签栏 + </body>）。
func panelShell(src string) (string, string) {
	kind, tab := panelPageKind(src)
	switch kind {
	case panelKindForm:
		header := `<header class="appbar"><a class="back" href="` + panelCancelHref(src) + `">取消</a><span class="spacer"></span><b class="page-title">` + template.HTMLEscapeString(panelPageTitle(src)) + `</b><span class="spacer"></span></header>`
		return `<body>` + header + `<main class="page">`, `</main></body>`
	case panelKindTab:
		header := `<header class="appbar"><a class="brand" href="/admin/">SWS Vault</a><span class="spacer"></span>`
		switch {
		case strings.HasPrefix(panelPageTitle(src), "密钥详情"):
			// 详情页左上角固定指向上级页面（A5）。
			header = `<header class="appbar"><a class="back" href="/admin/secrets">‹ 密钥</a><span class="spacer"></span>`
		case panelPageTitle(src) == "项目详情":
			// 详情页左上角固定指向上级页面（A5）。
			header = `<header class="appbar"><a class="back" href="/admin/projects">‹ 项目</a><span class="spacer"></span>`
		case panelPageTitle(src) == "设置":
			// 设置页本身就是右上角入口，不再重复链接。
		default:
			header += `<a href="/admin/settings">设置</a>`
		}
		header += `</header>`
		return `<body class="has-tabbar">` + header + `<main class="page">`, `</main>` + panelTabBar(tab) + `</body>`
	}
	// 其它页面沿用原来的顶栏，保持既有行为。
	shell := `<body><header class="appbar"><a class="brand" href="/admin/">SWS Vault</a><span class="spacer"></span><a href="/admin/">首页</a></header><main class="page">`
	if strings.Contains(src, `name="secret"`) && strings.Contains(src, `<title>接入项目</title>`) {
		shell = `<body><header class="appbar"><a class="brand" href="/admin/">SWS Vault</a><span class="spacer"></span><a class="back" href="/admin/quick/project">‹ 上一步</a></header><main class="page">`
	}
	return shell, `</main></body>`
}
