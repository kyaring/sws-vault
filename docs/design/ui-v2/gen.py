css = """
*{box-sizing:border-box}body{margin:0;background:#F2F2F7;font:16px/1.45 "Noto Sans CJK SC","Droid Sans Fallback",sans-serif;color:#1C1C1E;width:390px;min-height:844px;position:relative;padding-bottom:96px}
.top{display:flex;justify-content:space-between;align-items:center;padding:14px 16px 0;color:#2F4FD9;font-size:16px;min-height:44px}
.top b{font-weight:600}.plus{font-size:30px;line-height:1;font-weight:300}
h1{font-size:30px;margin:6px 16px 4px;font-weight:700}.lead{margin:0 16px 14px;color:#5B5B62;font-size:15px}
h2{font-size:13px;color:#5B5B62;font-weight:500;margin:18px 32px 6px;letter-spacing:.02em}
.g{background:#fff;border-radius:14px;margin:0 16px;overflow:hidden}
.r{display:flex;align-items:center;gap:12px;min-height:56px;padding:9px 16px;border-top:1px solid #E3E3E8}.r:first-child{border-top:0}
.r .t{flex:1}.r small{display:block;color:#5B5B62;font-size:13px}.chev{color:#C4C4CA;font-size:20px}
.ic{width:30px;height:30px;border-radius:8px;background:#E8ECFD;color:#2F4FD9;display:flex;align-items:center;justify-content:center;font-size:15px}
.ic.w{background:#FFF3DC;color:#8A5300}
.badge{font-size:12px;padding:2px 8px;border-radius:99px;background:#FFF3DC;color:#8A5300}
.ok{background:#E4F4E8;color:#1E7A3C}
.tw{width:46px;height:28px;border-radius:99px;background:#34C759;position:relative}.tw:after{content:"";position:absolute;right:2px;top:2px;width:24px;height:24px;border-radius:50%;background:#fff}
.tw.off{background:#E3E3E8}.tw.off:after{right:auto;left:2px}
.f{background:#fff;border-radius:14px;margin:0 16px;padding:4px 16px}
.f label{display:block;padding:10px 0;border-top:1px solid #E3E3E8;font-size:13px;color:#5B5B62}.f label:first-child{border-top:0}
.f .v{color:#1C1C1E;font-size:16px;margin-top:2px}.ph{color:#A0A0A8}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:0 16px}.chip{padding:8px 14px;border-radius:99px;background:#fff;font-size:15px}.chip.on{background:#2F4FD9;color:#fff}
.btn{display:block;margin:14px 16px 0;padding:14px;border-radius:14px;background:#2F4FD9;color:#fff;text-align:center;font-weight:600}
.btn.s{background:#E8ECFD;color:#2F4FD9}.btn.d{background:#FDE8E8;color:#C62828}
.tab{position:absolute;left:0;right:0;bottom:0;height:78px;background:rgba(249,249,251,.96);border-top:1px solid #E3E3E8;display:flex;justify-content:space-around;padding-top:8px;font-size:11px;color:#8E8E93}
.tab div{text-align:center}.tab i{display:block;font-style:normal;font-size:22px}.tab .on{color:#2F4FD9}
.hint{margin:8px 32px 0;color:#5B5B62;font-size:13px}
.done{text-align:center;padding:30px 16px 6px}.done .big{width:64px;height:64px;border-radius:50%;background:#E4F4E8;color:#1E7A3C;font-size:34px;line-height:64px;margin:0 auto 10px}
details{margin:0 16px}summary{background:#fff;border-radius:14px;padding:14px 16px;list-style:none;color:#1C1C1E}
.anno{position:absolute;bottom:88px;left:16px;font-size:14px !important;background:#FFE14D;color:#000;font-size:12px;padding:2px 8px;border-radius:6px}
.chk{width:22px;height:22px;border-radius:6px;border:2px solid #C4C4CA}.chk.on{background:#2F4FD9;border-color:#2F4FD9;color:#fff;font-size:14px;text-align:center;line-height:18px}
.seg{display:flex;margin:0 16px;background:#E3E3E8;border-radius:10px;padding:2px}.seg div{flex:1;text-align:center;padding:7px;border-radius:8px;font-size:14px}.seg .on{background:#fff;font-weight:600}
"""
tab = lambda on: '<div class="tab">' + ''.join(f'<div class="{"on" if n==on else ""}"><i>{i}</i>{n}</div>' for i,n in [("◆","密钥"),("▦","项目"),("☰","记录")]) + '</div>'
pages = {}
pages["1-keys"] = f"""<div class="anno">① 密钥标签（登录后首页）</div><div class="top"><b>SWS Vault</b><span>设置</span></div>
<div class="top" style="padding-top:0;min-height:0"><span></span><span class="plus">＋</span></div><h1>密钥</h1><p class="lead">值永远不会显示在面板上。</p>
<h2>未归入项目 · 1</h2><div class="g"><div class="r"><span class="ic w">⚑</span><span class="t">临时测试 Token<small>GitHub · 尾号 0007 · 还没人能用</small></span><span class="chev">›</span></div></div>
<h2>cf-dns</h2><div class="g"><div class="r"><span class="ic">◆</span><span class="t">博客 DNS 令牌<small>Cloudflare · 尾号 0001 · 2 个接入方</small></span><span class="chev">›</span></div></div>
<h2>blog</h2><div class="g"><div class="r"><span class="ic">◆</span><span class="t">GitHub PAT<small>GitHub · 尾号 0002 · 1 个接入方</small></span><span class="chev">›</span></div><div class="r"><span class="ic">◆</span><span class="t">Gitea 部署令牌<small>Gitea · 尾号 0003 · 已停用</small></span><span class="chev">›</span></div></div>{tab("密钥")}"""
pages["2-new"] = f"""<div class="anno">② 新建密钥</div><div class="top"><span>取消</span><b style="color:#1C1C1E">新建密钥</b><span style="opacity:.4">保存</span></div>
<h2>平台</h2><div class="chips"><span class="chip on">Cloudflare</span><span class="chip">GitHub</span><span class="chip">Gitea</span><span class="chip">其他</span></div>
<h2>内容</h2><div class="f"><label>名称<div class="v">博客 DNS 令牌</div></label><label>密钥值<div class="v ph">粘贴到这里，保存后不再显示</div></label></div>
<h2>放进项目（可选）</h2><div class="f"><label>项目<div class="v">cf-dns ›</div></label></div><p class="hint">不选就先放在「未归入项目」，任何接入方都用不了。</p>
<div class="btn">保存</div>"""
pages["3-saved"] = f"""<div class="anno">③ 存好了 → 直接接「发」</div><div class="done"><div class="big">✓</div><h1 style="margin:0">已保存</h1><p class="lead" style="margin:6px 0 0">博客 DNS 令牌 · Cloudflare · 尾号 0001<br>放在项目 cf-dns</p></div>
<div class="btn">给谁用 →</div><p class="hint" style="text-align:center;margin:8px 16px">生成一张通行证，让 AI 或脚本能代发请求</p><div class="btn s">完成</div>"""
pages["4-project"] = f"""<div class="anno">④ 项目详情</div><div class="top"><span>‹ 项目</span><span>编辑</span></div><h1>cf-dns</h1><p class="lead">Cloudflare DNS 令牌，给多个站点复用。</p>
<h2>密钥</h2><div class="g"><div class="r"><span class="ic">◆</span><span class="t">博客 DNS 令牌<small>Cloudflare · 尾号 0001</small></span><span class="chev">›</span></div><div class="r" style="color:#2F4FD9"><span class="ic">＋</span><span class="t">放入密钥<small>新建，或从未归入项目里选</small></span></div></div>
<h2>接入方</h2><div class="g"><div class="r"><span class="ic">◎</span><span class="t">blog-worker<small>仅代发 · 来源 IP 不限 · 正常</small></span><span class="chev">›</span></div><div class="r"><span class="ic">◎</span><span class="t">hark-ai<small>仅代发 · 10.0.0.0/8 · 正常</small></span><span class="chev">›</span></div></div>
<div class="btn">添加接入方</div>{tab("项目")}"""
pages["5-addclient"] = f"""<div class="anno">⑤ 添加接入方</div><div class="top"><span>取消</span><b style="color:#1C1C1E">添加接入方</b><span></span></div>
<h2>谁来调用</h2><div class="f"><label>名称<div class="v">hark-ai</div></label><label>备注<div class="v">Hark 改 DNS 用</div></label></div>
<h2>能用哪些密钥</h2><div class="g"><div class="r"><span class="chk on">✓</span><span class="t">博客 DNS 令牌<small>Cloudflare</small></span></div></div>
<h2>权限</h2><div class="seg"><div class="on">仅代发（推荐）</div><div>可取明文</div></div><p class="hint">仅代发：接入方拿不到密钥值，只能让 Vault 帮它发请求。</p>
<h2>来源 IP（可选）</h2><div class="f"><label>限制来源<div class="v ph">留空即不限，例如 10.0.0.0/8</div></label></div>
<div class="btn">生成通行证</div>"""
pages["6-client"] = f"""<div class="anno">⑥ 接入方详情（新增）</div><div class="top"><span>‹ cf-dns</span><span></span></div><h1>hark-ai</h1><p class="lead">Hark 改 DNS 用 · 创建于 10-16 07:20</p>
<div class="f"><label>权限<div class="v">仅代发</div></label><label>来源 IP<div class="v">10.0.0.0/8</div></label><label>状态<div class="v"><span class="badge ok">正常</span> · 最近使用 3 分钟前</div></label></div>
<h2>能用哪些密钥</h2><div class="g"><div class="r"><span class="t">博客 DNS 令牌<small>Cloudflare</small></span><span class="tw"></span></div><div class="r"><span class="t">备用 DNS 令牌<small>Cloudflare</small></span><span class="tw off"></span></div></div>
<div class="btn s">重新生成通行证</div><div class="btn d">停用</div>"""
pages["7-keydetail"] = f"""<div class="anno">⑦ 密钥详情</div><div class="top"><span>‹ 密钥</span><span></span></div><h1>博客 DNS 令牌</h1><p class="lead">Cloudflare · 尾号 0001 · 指纹 a0ca2795</p>
<div class="f"><label>项目<div class="v">cf-dns ›</div></label><label>最近使用<div class="v">3 分钟前 · hark-ai</div></label></div>
<h2>谁在用</h2><div class="g"><div class="r"><span class="t">blog-worker<small>仅代发</small></span><span class="tw"></span></div><div class="r"><span class="t">hark-ai<small>仅代发</small></span><span class="tw"></span></div></div>
<h2>&nbsp;</h2><details><summary>请求限制 <span style="float:right;color:#5B5B62">api.cloudflare.com ›</span></summary></details><p class="hint">平台模板已自动填好，一般不用改。</p>
<div class="btn s">轮换</div><div class="btn d">停用</div>"""
for k,v in pages.items():
    open(k+".html","w").write(f'<!doctype html><html lang="zh"><meta charset="utf-8"><style>{css}</style><body>{v}</body></html>')
