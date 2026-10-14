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

`--env-file FILE` for CLI URL/token/namespace settings requires exact mode 0600. Do not put tokens or values in shell command arguments or history.

## SV-20261015-01 — SWS Vault v1 delivery report

- Project: `sws-vault` (independent of VPS-Commander)
- Branch: `feat/v1-core`
- Acceptance baseline: task card commit `74a1ff7` (task card records original source baseline `a50eaae`)
- Final commit: `7f877b586a6b2eada2f3eb52dd2d9f0ce44d570b`
- Worktree status at SV-01 report creation: clean; no deployment, GitHub push, or merge back to main was performed.

### Milestone commits

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

### Verification

- `sh docs/process/check-task.sh SV-20261015-01`: PASS, exit 0. The script confirmed task card/baseline, allowed-path scope, size limits (3,708 non-test lines / 48 files against 12,000 / 80), `git diff --check`, normal Go tests, race tests, and acceptance script.
- `go test -count=1 ./...`: PASS across all packages.
- `go test -count=1 -race ./...`: PASS across all test-bearing packages.
- `go vet ./...` and `go build ./...`: PASS.
- Regression inventory: 38 Go test functions across `cmd` and `internal` at final code state; several packages intentionally contain no direct tests and are exercised through API/integration tests.
- Reverse verification: temporarily disabled fetch response redaction; `TestFetchPinsIPDropsAuthAndRedacts` failed as expected (`response exposed injected value`). Temporarily injected the sentinel into secret-list metadata; `TestSentinelNeverListedOrAudited` failed as expected (`list exposed sentinel`). Both temporary faults were reverted, then full checks passed.
- Secret-output checks use only conspicuous fake values such as `SENTINEL-VALUE-7f3a9c`; no real credentials were used.

### Implementation decisions

- Prefer restrictive defaults: loopback listener, exact host allowlists, private/HTTP access disabled unless explicitly bound, no wildcard hosts, DNS resolution pinned for outbound requests, redirects not followed, and capped/redacted response handling.
- Metadata/list/admin pages never intentionally return secret plaintext; `/v1/resolve` is the explicit plaintext boundary, while fetch injects credentials only into a bound outbound request.
- Client tokens and one-time intent tokens are stored as SHA-256 digests; administrator passwords use Argon2id (3 iterations, 64 MiB, 2 lanes, 16-byte salt, 32-byte output) through the explicitly permitted `golang.org/x/crypto` dependency.
- Forwarded client IP headers are trusted only when the socket peer matches configured trusted proxy CIDRs. Admin sessions have idle/absolute expiry; login has TOTP replay defense, lockout and incremental delay.
- Provider verification uses the same constrained outbound engine; failed verification does not persist the proposed secret and does not expose provider response bodies.
- When `SWSV_PUBLIC_BASE_URL` is absent, one-time intent URLs remain relative rather than fabricating a public origin.

### Known limitations / operational notes

- This is a development deliverable only; it has not been deployed or exposed to a network.
- Review `docs/security.md`, `docs/providers.md`, `docs/api.md`, and `docs/ops.md` before deployment. In particular, production TLS/reverse-proxy policy, backups, key custody, monitoring, and recovery procedures must be finalized for the actual host environment.
- KEK rotation is an offline maintenance operation: stop the service before rotating so no process retains a stale in-memory keyring.
- The embedded admin panel is intentionally minimal; the v1 implementation prioritizes access control, secret-handling boundaries, and auditability over advanced UI features.
