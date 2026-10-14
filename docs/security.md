# Security model and implementation decisions

## Threat model

Assume the SQLite database may be copied or inspected independently of the master key. Protect secret values at rest with per-secret data-encryption keys (DEKs), authenticated encryption, and associated data binding the namespace, secret ID, and type. Client tokens are stored as SHA-256 digests. Audit events contain identifiers and outcomes, never credential values, request headers, or response bodies.

The process, operating-system administrator, and any process explicitly given a resolved credential remain trusted. Memory zeroing is best-effort in Go and cannot guarantee removal of compiler/runtime copies. A compromised host or master key can expose stored values.

## Implementation decisions

- Prefer standard-library cryptography and a small number of moving parts. Use AES-256-GCM with a fresh random nonce and AAD scoped to the record identity.
- Encrypt each secret with a random DEK; wrap the DEK with the master key. The current implementation establishes the envelope format; KEK rotation and multi-version migration must be validated before production use.
- The master-key file must be created exclusively and have mode 0600. Startup rejects group/world permissions. Key material is never logged.
- Namespace boundaries fail closed: cross-namespace lookup returns 404. Authorization and scope checks fail closed.
- Default listener is loopback. Do not expose the service through a reverse proxy until trusted-proxy handling and the operations design have been reviewed.
- Values are accepted only in request bodies or stdin, never command-line flags. Examples and tests use fake sentinel values only.
- Until the full acceptance suite proves fetch SSRF defenses, response redaction, admin CSRF/TOTP, intent one-time use, and CLI output redaction, those incomplete surfaces are not production-ready.

## Plaintext boundaries

Plaintext is necessarily present while encrypting/decrypting in process memory. The intended v1 boundaries are the explicit resolve response, the child-process environment for `run`, and the injected outbound request header for `fetch`. These boundaries must be restricted by scope, binding, audit, and redaction. No list, admin page, log, or audit event may contain the value.

### Authentication and audit decisions

- Client credentials use a 32-byte cryptographically random token encoded as unpadded base64url and prefixed `swsv_`; only the SHA-256 digest is persisted. Creation is a local root-only CLI operation and prints the token once.
- Scopes are comma-separated and checked before dispatch. Namespace mismatches are intentionally indistinguishable from missing records. CIDR allowlists parse the socket peer address; forwarding headers are not trusted by the current listener.
- The in-process token bucket defaults to 60 requests per client per minute. It resets on restart and is not a distributed limiter; deployments must keep a single process until a shared limiter is designed.
- Audit events are structured fields only. No request bodies, authorization headers, or credential values are copied into audit records.

### Admin password hashing limitation

The approved `golang.org/x/crypto` module is not present in the local module cache, and outbound access to `proxy.golang.org` timed out during this task. The development panel currently uses Go's standard-library PBKDF2-HMAC-SHA256 (600,000 iterations) rather than the task-required Argon2id. This is a documented deviation, not equivalent completion; do not deploy until Argon2id is available and substituted with tests. No extra dependency was introduced.

### Outbound fetch decisions

- The fetch engine accepts exact host bindings only. It rejects URL userinfo, unapproved schemes, unapproved hosts, metadata IPs, and private/loopback/link-local addresses unless private access is explicitly enabled (metadata IPs remain blocked).
- DNS is resolved once per request and the transport dials the selected validated IP directly, preserving the original URL host for HTTP Host and TLS SNI. Environment proxies are disabled so they cannot bypass pinning.
- Redirects are not followed. Caller-provided Authorization, Cookie, Host, and X-Auth-* headers are discarded before provider headers are applied. Response bodies are limited to 1 MiB and response headers/body are redacted for raw, base64, and URL-encoded forms of the injected value.
- Generic header templates are limited to `{v}` and `{username}`. Host and header policy are explicit bindings; empty generic host bindings deny the request.
