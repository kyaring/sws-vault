# Security model and implementation decisions

## Threat model

Assume the SQLite database may be copied or inspected independently of the master key. Protect each secret value with a random per-record DEK and AES-256-GCM. The master key is never used directly as an AES key: HKDF-SHA256 derives separate `kek-wrap` and `fingerprint` subkeys. The `kek-wrap` subkey wraps DEKs; the fingerprint subkey keys HMAC-SHA256 fingerprints truncated to six bytes. Data AAD is exactly `ns|id|type|key_version`; DEK-wrap AAD is `ns|id|dek|key_version`. AAD mismatch or ciphertext tampering must fail closed.

Client tokens are stored as SHA-256 digests and the candidate/stored digests are confirmed with a constant-time comparison after lookup. Public metadata, panel listings, and MCP list responses mask bound usernames; the raw username remains in the internal binding record needed for provider injection (binding metadata is not independently encrypted). Audit events contain identifiers and outcomes, never credential values, request headers, or response bodies. The process, operating-system administrator, and any process explicitly given a resolved credential remain trusted. Memory zeroing is best-effort in Go and cannot guarantee removal of compiler/runtime copies. A compromised host or master key can expose stored values.

## Implementation decisions

- Prefer standard-library cryptography and a small number of moving parts. Use a fresh random GCM nonce for every encryption and bind record identity and key version in AAD.
- Encrypt each secret with a random DEK; wrap the DEK with an HKDF-derived KEK subkey. KEK rotation transactionally re-wraps DEKs, re-encrypts ciphertext with the new version in AAD, and recalculates keyed fingerprints. Old key files remain until all records are verified.
- The master-key file must be created exclusively and have mode 0600. Startup rejects group/world permissions. Key material is never logged.
- Default paths are `/etc/sws-vault/master.key` and `/var/lib/sws-vault/vault.db`; use `--config` or `SWSV_*` variables to override them. When `SWSV_DATA_DIR` is set alone, the database and key paths are derived under that directory for isolated development.
- Namespace boundaries fail closed: cross-namespace lookup returns 404. Authorization and scope checks fail closed. Client tokens have expiry, disable state, CIDR allowlists, and a configurable per-minute token bucket (`SWSV_RATE_LIMIT_PER_MINUTE`, default 60).
- Default listener is loopback. Forwarding headers are ignored unless the socket peer is in configured `SWSV_TRUSTED_PROXY_CIDRS`; then the chain is traversed from right to left to find the first untrusted address.
- Values are accepted in request bodies or stdin, never command-line flags. Examples and tests use fake sentinel values only.
- Admin sessions use opaque random cookies, 15-minute idle timeout, 8-hour absolute timeout, SameSite Strict, HttpOnly, Secure when the configured public base URL is HTTPS, and CSRF checks. TOTP replay is rejected. Five consecutive failures lock only the source IP for 15 minutes; other source IPs remain eligible to log in, while incremental delays provide global backoff. Expired sessions, rate-limit buckets, and login-attempt entries are pruned periodically.
- Outbound fetch accepts exact host bindings only. It rejects URL userinfo, unapproved schemes, unapproved hosts, metadata IPs, and private/loopback/link-local addresses unless private access is explicitly enabled (metadata IPs remain blocked). DNS is resolved once per request and the transport dials the selected validated IP directly. Environment proxies are disabled.
- Redirects are not followed. Caller-provided Authorization, Cookie, Host, and X-Auth-* headers are discarded before provider headers are applied. Response bodies are limited to 1 MiB and response headers/body are redacted for raw, base64, and URL-encoded forms of the injected value.
- Generic header templates are limited to `{v}` and `{username}`. Host and header policy are explicit bindings; generic fetch requires an explicit host allowlist.

## Plaintext boundaries

Plaintext is necessarily present while encrypting/decrypting in process memory. The resolve response carries `Cache-Control: no-store` and is allowed only when both the client has `resolve` scope and the secret binding has `allow_resolve=true`. The embedded admin assets handler serves only exact asset paths and returns 404 for directory paths. The intended v1 boundaries are the explicit resolve response, the child-process environment for `run`, and the injected outbound request header for `fetch`. These boundaries must be restricted by scope, binding, audit, and redaction. No list, admin page, log, or audit event may contain the value.


## Password hashing

Administrator passwords use Argon2id via the explicitly permitted `golang.org/x/crypto` dependency, with 3 iterations, 64 MiB memory, 2 lanes, a 16-byte random salt, and a 32-byte output. Password input is read from stdin without terminal echo. TOTP seeds and session CSRF material are not written to logs.
