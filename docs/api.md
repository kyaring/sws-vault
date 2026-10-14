

## SV-20261015-02 — 审核整改交付报告

- 任务卡：docs/tasks/SV-20261015-02.md（main d70757d）；工作分支 feat/v1-core。
- 为同步审核卡和报告，将 main 合入本分支（merge commit 6d4f413）；**没有合并回 main、没有推送 GitHub、没有部署**。
- 整改提交：
  - f169d9388329b6d67296b3394af8afc23e6f3fdc — SV-02: inject commit into versioned build。
  - d34d07644e3adcde754084ba5719d323fe1dd037 — SV-02: harden API, admin, and fetch boundaries。
  - 3f1ad2e41d5a745f7e623a61807242eb27a42d2f — SV-02: align operations and security documentation。
- 总测试函数数：52（含新增回归测试）。所有值均为假值；没有使用真实凭据。

### 每条整改与提交、测试对应关系

| 条目 | 整改 | 提交 | 新增测试 / 验收 |
|---|---|---|---|
| 1 | make build 通过 ldflags 注入当前 12 位 commit；README、ops 统一使用该构建方式 | f169d93 | TestVersionTextUsesInjectedCommit；最终 ./bin/swsvault version 与 git rev-parse --short=12 HEAD 比对 |
| 2 | resolve 必须同时通过 resolve scope 与 allow_resolve 绑定门禁 | d34d076 | TestResolveRequiresAllowResolveAndNoStore |
| 3 | resolve 所有响应设置 Cache-Control: no-store | d34d076 | TestResolveRequiresAllowResolveAndNoStore（成功和拒绝分支均断言） |
| 4 | master.key 权限 0644/0640 拒绝；0600 可用 | f169d93 | TestLoadKeyringEnforcesMasterKeyPermissions、TestServeRejectsLooseMasterKeyPermissions |
| 5 | SSRF 边界及调用方 X-Auth-*、Cookie 丢弃行为覆盖 | d34d076 | TestFetchSSRFBoundaryVariants、TestFetchPinsIPDropsAuthAndRedacts |
| 6 | Cookie 的 HttpOnly、SameSite=Strict、HTTPS Secure、8 小时绝对超时 | d34d076 | TestAdminCookieAttributesAndAbsoluteTimeout |
| 7 | /admin/assets/ 目录请求 404，仅允许精确资源路径 | d34d076 | TestAdminAssetDirectoryListingDisabled |
| 8 | 连续 5 次失败按来源 IP 锁定 15 分钟；全局仅退避、不硬锁；可信代理 IP 仍遵守配置 | d34d076 | TestAdminLockoutScopedToSourceIP、既有 TestAdminLocksAfterFiveFailures |
| 9 | sessions、rateState、loginAttempts 定期清理 | d34d076 | TestMemoryTablesCleanupExpiredEntries；清理 ticker 每分钟运行 |
| 10 | 管理面板改绑定时复用主机格式校验，非法主机返回 400 | d34d076 | TestAdminBindingRejectsInvalidHost、TestValidHostBindingRejectsURLAndMalformedPorts |
| 11 | 删除 generate.go 空循环 | d34d076 | TestGenerateSourceHasNoEmptyLoop |
| 12 | list、管理面板和 MCP 列表中的 username 打码；内部绑定记录保留原文供 provider 注入 | d34d076 | TestUsernameMaskedInMetadataListPanelAndMCP |
| 13 | 客户端令牌哈希查询后使用常数时间比较复核 | d34d076 | TestClientTokenHashConfirmationIsConstantTime |
| 14 | SV-01、SV-02 报告统一到本文件；修正 ops 与 security 说明 | 3f1ad2e | 文档核对；docs/ops.md 不再将已实现的 Argon2id/provider 验证列为待完成前置条件 |

### 三项反向验证

1. **移除 allow_resolve 门禁**：TestResolveRequiresAllowResolveAndNoStore 按预期失败，返回了 200 并暴露假值 FAKE-RESOLVE-ONLY。
2. **恢复目录列表 FileServer**：TestAdminAssetDirectoryListingDisabled 按预期失败，观测到 /admin/assets/ status=200 want=404。
3. **把按 IP 锁定改回全局硬锁**：TestAdminLockoutScopedToSourceIP 按预期失败，IP B 被错误返回 429。

三项变异均在临时工作树改动中执行，随后全部还原；没有将故意错误的代码提交。还原后 git diff --check 干净，普通测试和 race 测试通过。

### 验收与实现决定

- go test -count=1 ./...：通过。
- go test -count=1 -race ./...：通过（setsid/nohup 后台执行）。
- go vet ./...、go build ./...、gofmt 和 git diff --check：通过。
- sh docs/process/check-task.sh SV-20261015-02：通过；基线 d70757d，改动范围合规，规模 3,815 非测试行 / 49 个文件（上限 12,000 / 80），包含 acceptance 与 race 检查。
- README 快速开始冒烟：通过；临时目录完成 keygen、admin init、client create、serve、healthz、write、list、resolve；list/create 未泄漏假值，resolve 只在显式请求时返回假值。
- make build 生成的 ./bin/swsvault version 与 git rev-parse --short=12 HEAD 完全一致；最终报告提交后再次执行同一检查和 README 冒烟。
- 主机名大小写会规范化后按精确 allowlist 匹配；尾点主机名只有 allowlist 也显式带尾点时才匹配。userinfo、IPv6 loopback/ULA、解析到 loopback 的十进制 IP 和云 metadata IP 均按当前策略拒绝。
- 管理员登录锁定以 sourceIP 为键；只有配置的可信代理来源才会读取 X-Forwarded-For。全局退避最多 1 秒，不会对其他 IP 施加硬锁。
- 本次仅开发和测试；没有部署，没有修改 /etc 或 /var/lib，没有 GitHub push，也没有合并回 main。部署前仍须按实际环境复核 TLS/反向代理、备份、密钥托管、监控和恢复流程。
