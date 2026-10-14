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

## v1 delivery report

The final delivery report is maintained with the task-reported notification. It records each M1–M8 implementation commit, final acceptance output, test count, reverse-redaction checks, implementation decisions, and known limitations. Argon2id is implemented with 3 iterations, 64 MiB, 2 lanes, 16-byte salt, and 32-byte output via the explicitly allowed `golang.org/x/crypto` module.
