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
