# SWS Vault v1 API and CLI

## Configuration

The process accepts a `KEY=VALUE` config file via `--config FILE`; explicit `SWSV_*` environment variables override file values. Defaults are `SWSV_MASTER_KEY_PATH=/etc/sws-vault/master.key`, `SWSV_DB_PATH=/var/lib/sws-vault/vault.db`, and `SWSV_LISTEN=127.0.0.1:9531`. `SWSV_DATA_DIR` set by itself derives `master.key` and `vault.db` below that directory for isolated tests. `SWSV_PUBLIC_BASE_URL` controls absolute one-time intent links; when empty, the API returns a relative `/i/<token>` URL. `SWSV_RATE_LIMIT_PER_MINUTE` defaults to 60. `SWSV_TRUSTED_PROXY_CIDRS` is a comma-separated list; forwarded headers are ignored unless the socket peer belongs to a configured CIDR.

## Authentication and scopes

Send `Authorization: Bearer <client-token>`. The token is stored as a SHA-256 digest. Clients have namespace, scopes, optional CIDR restrictions, optional expiry, and disable state. Missing/invalid/expired/disabled token: 401; CIDR mismatch or missing scope: 403; cross-namespace lookup: 404; rate limit: 429. Supported scopes are `secrets:list`, `secrets:write`, `fetch`, `resolve`, and `intents:create`.

## REST endpoints

| Method and path | Scope | Behavior |
|---|---|---|
| `GET /healthz` | none | Health status only |
| `GET /v1/secrets?ns=<ns>` | `secrets:list` | Metadata only; never returns secret values |
| `POST /v1/secrets` | `secrets:write` | Stores request-body value and returns metadata only |
| `PUT /v1/secrets/<id>/value` | `secrets:write` | Rotates the value and returns metadata only |
| `POST /v1/generate` | `secrets:write` | Generates a value and stores it; returns metadata only |
| `POST /v1/resolve` | `resolve` plus binding `allow_resolve` | The sole REST endpoint that intentionally returns plaintext |
| `POST /v1/fetch` | `fetch` | Resolves a bound value, injects provider headers into one pinned outbound request, and redacts response headers/body |
| `POST /v1/intents` | `intents:create` | Creates a ten-minute, one-use entry URL; stores only the token hash |

| `POST /mcp` | per-tool scope | Streamable HTTP JSON-RPC MCP endpoint |

A secret reference has the form `vault:<namespace>/<id>`. The metadata response contains `id`, `ns`, `label`, `provider`, `type`, `preview`, `fingerprint`, `status`, timestamps, and bindings. It never contains ciphertext, wrapped DEKs, key material, or the plaintext value.


`POST /v1/resolve` returns the plaintext `value` and the bound `username` in the same response, only when the client has `resolve` scope and the secret binding has `allow_resolve=true`. It always sets `Cache-Control: no-store`. The list endpoint, admin panel, and MCP list metadata continue to mask `bindings.username`; resolve is the explicit plaintext boundary for both value and username.

The admin panel's binding-update action validates host entries and returns HTTP 400 for malformed hosts, URLs with paths or userinfo, query/fragment components, and invalid ports. Host matching remains exact after hostname case normalization.

### MCP tools

`tools/list` exposes `vault_list`, `vault_fetch`, and `vault_intent`. `vault_list` reuses namespace/scope checks; `vault_fetch` reuses the REST fetch engine and redaction; `vault_intent` creates the same one-time entry flow. The MCP handler returns JSON-RPC errors without embedding credential values in error text.

### Provider verification

When the admin panel's “保存前验证” option is enabled, SWS Vault sends a minimal verification request through the same host allowlist, resolver pinning, timeout, and response cap as fetch. Cloudflare API token uses `GET https://api.cloudflare.com/client/v4/user/tokens/verify`; Cloudflare global key uses `GET https://api.cloudflare.com/client/v4/user`; GitHub PAT uses `GET https://api.github.com/user`; Gitea token uses `GET <base_url>/api/v1/user`. A failed check does not store the secret. Only the status code or a generic verification failure is returned; provider response bodies are never surfaced.

## CLI

- `swsvault keygen [--out PATH]`: creates a key file exclusively with mode 0600; no key material is printed.
- `swsvault admin init`: reads the password twice from stdin without terminal echo and prints a one-time TOTP enrollment URI. `admin reset-totp` verifies the current password and resets replay/lockout state. `admin rotate-kek` is an offline maintenance command: stop the service first, then it rewraps all DEKs and updates AAD/key versions transactionally.
- `swsvault client create --ns NS --name NAME --scopes SCOPE,... [--cidrs CIDR,...] [--expires RFC3339]`: root-only local operation; token is printed once and only its digest is stored.
- `swsvault capture --ns NS --label LABEL --provider PROVIDER`: reads the secret from stdin, never from a flag, and prints only ID/preview.
- `swsvault run --env NAME=vault:NS/ID -- COMMAND ARGS...`: resolves references and puts values in child environment variables; stdout/stderr are redacted and child exit codes pass through.
- `swsvault git-credential get|store|erase`: implements Git's credential-helper protocol; only `get` resolves an explicitly host-bound GitHub/Gitea credential. `store` and `erase` are no-ops.
- `make build`: builds `./bin/swsvault` with the current 12-character Git commit injected; `./bin/swsvault version` prints that commit.

`--env-file FILE` for CLI URL/token/namespace settings requires exact mode 0600. Do not put tokens or values in shell command arguments or history.

## v1 交付说明

### SV-01 — 核心交付报告

- Project: `sws-vault` (independent of VPS-Commander)
- Branch: `feat/v1-core`
- Acceptance baseline: task card commit `74a1ff7` (task card records original source baseline `a50eaae`)
- Final commit: `7f877b586a6b2eada2f3eb52dd2d9f0ce44d570b`
- Worktree status at report creation: clean; no deployment, GitHub push, or merge performed.

#### Milestone commits

| Milestone | Commit | Delivery |
|---|---|---|
| M1 | `d4c3925` | Service skeleton, encrypted storage primitives |
| M2 | `1866a78` | Versioned keyring and DEK rewrapping |
| M3 | `ff0cbde` | Scoped clients, namespace isolation, audit and rate limiting |
| M4 | `34bca63` | REST metadata/write/generate/resolve and one-time intents |
| M5 | `bbace4b` | Admin login, TOTP replay defense, CSRF and management panel |
| M6 | `45f9e41` | Bound outbound fetch, pinned resolution and response redaction |
| M7 | `0871bcc` | MCP tools and CLI secret-resolution workflows |
| M8 | `7f877b5` | Hardening, documentation, regression and acceptance tests |

#### Verification

- `sh docs/process/check-task.sh SV-20261015-01`: PASS, exit 0. The script confirmed task card/baseline, allowed-path scope, size limits (3,708 non-test lines / 48 files against 12,000 / 80), `git diff --check`, normal Go tests, race tests, and acceptance script.
- `go test -count=1 ./...`: PASS across all packages.
- `go test -count=1 -race ./...`: PASS across all test-bearing packages.
- `go vet ./...` and `go build ./...`: PASS.
- Regression inventory: 38 Go test functions across `cmd` and `internal` at final code state; several packages intentionally contain no direct tests and are exercised through API/integration tests.
- Reverse verification: temporarily disabled fetch response redaction; `TestFetchPinsIPDropsAuthAndRedacts` failed as expected (`response exposed injected value`). Temporarily injected the sentinel into secret-list metadata; `TestSentinelNeverListedOrAudited` failed as expected (`list exposed sentinel`). Both temporary faults were reverted, then full checks passed.
- Secret-output checks use only conspicuous fake values such as `SENTINEL-VALUE-7f3a9c`; no real credentials were used.

#### Implementation decisions

- Prefer restrictive defaults: loopback listener, exact host allowlists, private/HTTP access disabled unless explicitly bound, no wildcard hosts, DNS resolution pinned for outbound requests, redirects not followed, and capped/redacted response handling.
- Metadata/list/admin pages never intentionally return secret plaintext; `/v1/resolve` is the explicit plaintext boundary, while fetch injects credentials only into a bound outbound request.
- Client tokens and one-time intent tokens are stored as SHA-256 digests; administrator passwords use Argon2id (3 iterations, 64 MiB, 2 lanes, 16-byte salt, 32-byte output) through the explicitly permitted `golang.org/x/crypto` dependency.
- Forwarded client IP headers are trusted only when the socket peer matches configured trusted proxy CIDRs. Admin sessions have idle/absolute expiry; login has TOTP replay defense, lockout and incremental delay.
- Provider verification uses the same constrained outbound engine; failed verification does not persist the proposed secret and does not expose provider response bodies.
- When `SWSV_PUBLIC_BASE_URL` is absent, one-time intent URLs remain relative rather than fabricating a public origin.

#### Known limitations / operational notes

- This is a development deliverable only; it has not been deployed or exposed to a network.
- Review `docs/security.md`, `docs/providers.md`, `docs/api.md`, and `docs/ops.md` before deployment. In particular, production TLS/reverse-proxy policy, backups, key custody, monitoring, and recovery procedures must be finalized for the actual host environment.
- KEK rotation is an offline maintenance operation: stop the service before rotating so no process retains a stale in-memory keyring.
- The embedded admin panel is intentionally minimal; the v1 implementation prioritizes access control, secret-handling boundaries, and auditability over advanced UI features.

### SV-02 — 第一轮审核整改报告

- 任务卡：docs/tasks/SV-20261015-02.md（main d70757d）；工作分支 feat/v1-core。
- 为同步审核卡和报告，将 main 合入本分支（merge commit 6d4f413）；**没有合并回 main、没有推送 GitHub、没有部署**。
- 整改提交：
  - f169d9388329b6d67296b3394af8afc23e6f3fdc — SV-02: inject commit into versioned build。
  - d34d07644e3adcde754084ba5719d323fe1dd037 — SV-02: harden API, admin, and fetch boundaries。
  - 3f1ad2e41d5a745f7e623a61807242eb27a42d2f — SV-02: align operations and security documentation。
- 总测试函数数：52（含新增回归测试）。所有值均为假值；没有使用真实凭据。

#### 每条整改与提交、测试对应关系

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

#### 三项反向验证

1. **移除 allow_resolve 门禁**：TestResolveRequiresAllowResolveAndNoStore 按预期失败，返回了 200 并暴露假值 FAKE-RESOLVE-ONLY。
2. **恢复目录列表 FileServer**：TestAdminAssetDirectoryListingDisabled 按预期失败，观测到 /admin/assets/ status=200 want=404。
3. **把按 IP 锁定改回全局硬锁**：TestAdminLockoutScopedToSourceIP 按预期失败，IP B 被错误返回 429。

三项变异均在临时工作树改动中执行，随后全部还原；没有将故意错误的代码提交。还原后 git diff --check 干净，普通测试和 race 测试通过。

#### 验收与实现决定

- go test -count=1 ./...：通过。
- go test -count=1 -race ./...：通过（setsid/nohup 后台执行）。
- go vet ./...、go build ./...、gofmt 和 git diff --check：通过。
- sh docs/process/check-task.sh SV-20261015-02：通过；基线 d70757d，改动范围合规，规模 3,815 非测试行 / 49 个文件（上限 12,000 / 80），包含 acceptance 与 race 检查。
- README 快速开始冒烟：通过；临时目录完成 keygen、admin init、client create、serve、healthz、write、list、resolve；list/create 未泄漏假值，resolve 只在显式请求时返回假值。
- make build 生成的 ./bin/swsvault version 与 git rev-parse --short=12 HEAD 完全一致；最终报告提交后再次执行同一检查和 README 冒烟。
- 主机名大小写会规范化后按精确 allowlist 匹配；尾点主机名只有 allowlist 也显式带尾点时才匹配。userinfo、IPv6 loopback/ULA、解析到 loopback 的十进制 IP 和云 metadata IP 均按当前策略拒绝。
- 管理员登录锁定以 sourceIP 为键；只有配置的可信代理来源才会读取 X-Forwarded-For。全局退避最多 1 秒，不会对其他 IP 施加硬锁。
- 本次仅开发和测试；没有部署，没有修改 /etc 或 /var/lib，没有 GitHub push，也没有合并回 main。部署前仍须按实际环境复核 TLS/反向代理、备份、密钥托管、监控和恢复流程。
