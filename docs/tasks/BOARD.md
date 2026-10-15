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
| SV-20261015-06 | 面板快速流程 + 网页扫码绑定 TOTP（含补充 F/G） | GPT | rechecked-pass（卡面口径 reviewed-pass） | 17:40 RikkaHub-1 第二轮复审通过（问题 1–4 全部闭环；1 建议＝两处新增断言强度不足）；报告 docs/reviews/SV-20261015-06-review.md「第二轮复审」；被审提交 5814212 | 2026-10-15 17:40 |
