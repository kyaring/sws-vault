# 看板：sws-vault

| 编号 | 标题 | 开发者 | 状态 | 说明 | 更新 |
|---|---|---|---|---|---|
| SV-20261015-01 | v1 核心（存、录、调、面板、平台模板、MCP、CLI）一次性大单 | GPT | merged（b8ba36a，OPC 11:53） | 04:28 交付 e5b8546（M1-M8）；05:06 RikkaHub-1 审核 CHANGES REQUESTED，报告 docs/reviews/SV-20261015-01-review.md（1 阻塞：version 不输出 commit；3 一般：resolve allow_resolve / resolve no-store / 主密钥权限 缺测试；安全行为本身全部成立） | 2026-10-15 05:06 |
| RV-SV-20261015-01 | 审核 SV-20261015-01（e5b8546） | RikkaHub-1 | done | Hark 04:58 派发；05:06 完成，结论 CHANGES REQUESTED，报告 docs/reviews/SV-20261015-01-review.md | 2026-10-15 05:06 |
| SV-20261015-02 | 返工：v1 审核意见整改（1 阻塞，3 一般，另有建议升级为必改） | GPT | merged（b8ba36a，OPC 11:53） | 05:56 RikkaHub-1 复审 CHANGES REQUESTED（被审提交 4ab69e8a1000）；报告 docs/reviews/SV-20261015-02-review.md | 2026-10-15 05:56 |
| RV-SV-20261015-02 | 审核 SV-02 返工（4ab69e8） | RikkaHub-1 | verified（Hark 06:10 终签，同意 CHANGES REQUESTED，问题 2 升级为阻塞） | Hark 05:48 派发；05:56 完成，结论 CHANGES REQUESTED，报告 docs/reviews/SV-20261015-02-review.md | 2026-10-15 05:56 |
| SV-20261015-03 | 返工 R2：恢复 api.md、修 git-credential 用户名回归、ops 矛盾句、两条测试改为行为测试 | GPT | merged（b8ba36a，OPC 11:53） | 06:56 RikkaHub-1 复审 CHANGES REQUESTED（被审提交 74688206b5a5；6 条必改全部满足，卡面验收第 1 条按字面不可满足需裁定）；报告 docs/reviews/SV-20261015-03-review.md | 2026-10-15 06:56 |
| SV-v1-leftovers | SV-03 遗留 3 条建议（v1 合并后开卡） | GPT | 并入 SV-20261015-04 | 见 SV-20261015-03.md 勘误 | 2026-10-15 07:35 |
| SV-20261015-04 | S-6 测试部署包（Hub 本机，内网 192.168.20.132:9531）+ v1 遗留两项 | GPT | verified @6b91d1b（Hark 12:35）→ merged | 12:30 RikkaHub-1 全量审核 reviewed-pass（待裁定 1 项：交付说明缺验收结果）；报告 docs/reviews/SV-20261015-04-review.md；被审提交 6b91d1b | 2026-10-15 12:30 |
| SV-20261015-05 | S-6 实装：Hub 本机上线测试版（192.168.20.132:9531） | Hark | in-progress（3–5 步已完成 12:35，在跑；等 OPC 在面板做初始化和 TOTP，之后第 7 步备份） | 每一步都要 OPC 批准；防火墙只放行 192.168.20.0/24 | 2026-10-15 12:10 |
| RV-SV-20261015-04 | 审核 S-6 部署包（6b91d1b），全量 | RikkaHub-1 | done（reviewed-pass daf27e0；Hark verified） | Hark 12:15 派发；12:30 完成，结论 reviewed-pass，报告 docs/reviews/SV-20261015-04-review.md | 2026-10-15 12:30 |
| SV-20261015-06 | 面板快速流程 + 网页扫码绑定 TOTP（含补充 F/G） | GPT | merged+deployed（2a0ab42） | 17:55 Hark 终签 verified @5814212；OPC 17:47 定先修遗留 4 项再合并 → SV-20261015-07（同分支）；OPC 19:47 批准，19:48 合并、upgrade 完成：healthz 200，只监听 192.168.20.132:9531，9521 不受影响，.prev 为 12:34 的版本，升级前备份为 vault-20261015-114819 | 2026-10-15 19:50 |
| SV-20261015-07 | 修复 SV-06 遗留 4 项：Gitea 自建地址、保留名防护和测试、去掉写死地址、加强断言（同分支 feat/s6-quickflow，基线 5814212） | GPT | merged+deployed（2a0ab42） | RikkaHub-1 复审 PASS（6797a77）；Hark 19:50 终签；遗留建议：Gitea 非默认端口被丢（出站被拒，属于安全失败）；待 OPC 批准与 SV-06 一起合并部署；OPC 19:47 批准，19:48 合并、upgrade 完成：healthz 200，只监听 192.168.20.132:9531，9521 不受影响，.prev 为 12:34 的版本，升级前备份为 vault-20261015-114819 | 2026-10-15 19:50 |

| SV-followups-0607 | 后续建议：Gitea 非默认端口；保留名测试已补；upgrade.sh 重启后立即 curl 未等待（19:48 实测退出码 7，服务实际正常）；SWSV_PUBLIC_BASE_URL 未配置 | — | backlog | 与 UI 卡之后统一开卡 | 2026-10-15 19:50 || SV-20261016-01 | 管理面板 UI v1（按 Hark 设计稿 docs/design/ui/ 实施） | GPT | ready | OPC 01:30 定稿；功能和安全由 RikkaHub-1 审核，UI 由 Hark 验收；规模上限 1800 行 / 30 文件 | 2026-10-16 01:35 |
| SV-20261016-02 | 返工：UI v1 验收意见整改（同分支 feat/ui-v1） | GPT | merged dfb7759 + deployed dfb77598b566（OPC 02:59 批准，03:00 部署） | Hark UI 复验 02:30 PASS（剩 3 条 Low）；功能审核 RV-SV-20261016-01 → RikkaHub-1 | 2026-10-16 03:01 |
| RV-SV-20261016-01 | 审核：UI v1（01+02）功能与安全全量审核 @a6258a5 | RikkaHub-1 | done：CHANGES REQUESTED（Hark 02:40 复核确认，评 99） | 阻塞 admin.js 404；待裁定项判为卡面缺陷 → SV-20261016-03 | 2026-10-16 02:40 |
| SV-20261016-03 | 修复 admin.js 404（RV-01 阻塞项）+ UI 三条 Low | GPT | merged dfb7759 + deployed dfb77598b566（OPC 02:59 批准，03:00 部署） | 03:0x RikkaHub-1 复审通过（阻塞项已修：admin.js 200 + 遍历断言；建议 1–3 已处理；1 建议＝交付消息缺逐项/验收结果）；报告 docs/reviews/SV-20261016-03-review.md；被审提交 875aa04 | 2026-10-16 03:01 |
| BL-upgrade-healthz | backlog：upgrade.sh 重启后立即 curl，退出码 7（第 2 次复现，10-16 03:00），需加入重试/等待 | — | backlog | — | 2026-10-16 03:01 |
| SV-20261016-04 | 接入项目默认只能代发，取明文可选，可锁来源 IP（OPC 03:24） | RikkaHub-1 | merged 2baae76 + deployed cb86accd754c（OPC 04:14 批准） | feat/client-fetch-only | 2026-10-16 04:16 |
| SV-20261016-05 | 项目与接入方分两步 + 「所有密钥」页改版 + SV-04 三条 Low（OPC 04:49 提出） | RikkaHub-1 | verified（随 SV-06 合并终签 @e99d60b，Hark 07:10） | 分支 feat/project-clients；规模 1400 行 / 18 文件；Hark 全量审核 | 2026-10-16 07:10 |
| SV-20261016-06 | 返工：SV-05 审核意见（空授权列表语义、使用范围页保留 no_client_access、3 条 Low） | RikkaHub-1 | verified（Hark 07:10 全量复审 @e99d60b；待 OPC 批准合并和部署） | 同分支 feat/project-clients，先 merge main；报告 docs/reviews/RV-SV-20261016-05.md | 2026-10-16 07:10 |
