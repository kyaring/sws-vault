package api

import "net/http"

// adminSettings 渲染设置页（SV-20261016-07 A2）：修改密码、两步验证、退出登录三行。
// 原来的 /admin/password 与 /admin/totp/enroll 地址不变，只是改成从这里进入。
func (s *Server) adminSettings(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.adminSession(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		adminErrOut(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	render(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>设置</title><h1>设置</h1><div class="group"><a class="row" href="/admin/password"><span class="t">修改密码<small>换一个只有你知道的密码</small></span></a><a class="row" href="/admin/totp/enroll"><span class="t">两步验证<small>登录时多要一个验证码</small></span></a><form class="row-form" method="post" action="/admin/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="row" type="submit"><span class="t">退出登录<small>结束这次登录</small></span></button></form></div>`, map[string]any{"CSRF": sess.csrf})
}
