# Operations draft (not deployed)

This document is a deployment proposal only. This development task does not create systemd units, modify `/etc` or `/var/lib`, open network ports, or install the binary.

## Runtime layout

- Run one dedicated service account with write access only to the chosen SWS Vault data directory.
- Keep `master.key` and versioned `master.key.vN` files mode 0600. Store them separately from the SQLite database and do not place either in the repository, web root, or backup bundle together.
- Keep the listener on `127.0.0.1:9531` unless a reviewed deployment card specifies another private binding.
- Do not deploy until Argon2id password hashing and provider pre-save verification are complete and the full acceptance gate passes.

## Illustrative systemd unit

```ini
[Unit]
Description=SWS Vault
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=swsvault
Group=swsvault
WorkingDirectory=/opt/sws-vault
Environment=SWSV_DATA_DIR=/var/lib/sws-vault
Environment=SWSV_LISTEN=127.0.0.1:9531
Environment=SWSV_PUBLIC_BASE_URL=https://vault.example.invalid
ExecStart=/opt/sws-vault/swsvault serve
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sws-vault

[Install]
WantedBy=multi-user.target
```

This is a draft example, not an installed unit. Review filesystem paths, user/group, and hardening against the actual deployment before use.

## Reverse proxy

- Terminate TLS at a trusted proxy and keep the upstream listener private.
- Forward `X-Forwarded-For` only from explicitly configured proxy IPs. Never trust arbitrary caller-supplied forwarding headers. The current application uses the socket peer IP and does not trust forwarding headers.
- Preserve `Cache-Control: no-store` on resolve responses; do not cache `/v1`, `/admin`, `/mcp`, or `/i` responses.
- Do not log authorization headers, request bodies, form bodies, or response bodies. Access logs should omit query strings on one-time intent links because the path token is a bearer capability.
- Do not enable public exposure until the admin hashing deviation is resolved and the SSRF/redaction tests pass in the release build.

## Backups

1. Quiesce writes or use SQLite's consistent backup API to create a database snapshot.
2. Back up the database separately from the master key files. Encrypt and access-control each backup independently.
3. Preserve all versioned master key files still referenced by `secrets.key_version`; removing an old key before all DEKs are rewrapped makes records unreadable.
4. Test restore in an isolated temporary directory using fake test records before relying on the backup.

## Recovery outline

1. Restore the database to a private directory with restrictive permissions.
2. Restore the matching versioned key files separately and verify mode 0600.
3. Run the binary's local health check and read-only metadata tests on loopback.
4. Verify old records can be decrypted through an authorized test resolve and that list/admin/audit/log outputs do not contain the sentinel.
5. Switch traffic only after the security review and the task acceptance script pass. Recovery is not complete if a key version referenced by the database is missing.

## Key rotation maintenance

`swsvault admin rotate-kek` must be run with the service stopped so no process continues using an in-memory keyring from before rotation. It writes a new versioned key file with exclusive creation and mode 0600, then transactionally rewraps each DEK, re-encrypts the secret with the new key-version AAD, and recalculates the fingerprint. If rotation fails, keep all key versions and restore service only after a read-only resolve smoke test confirms old values remain readable.
# SV-20261015-01 — SWS Vault v1 delivery report

- Project: `sws-vault` (independent of VPS-Commander)
- Branch: `feat/v1-core`
- Acceptance baseline: task card commit `74a1ff7` (task card records original source baseline `a50eaae`)
- Final commit: `e5b8546f2618047b5ddc231cc57b8267c9893203`
- Worktree status at report creation: clean; no deployment, GitHub push, or merge performed.

## Milestone commits

| Milestone | Commit | Delivery |
|---|---|---|
| M1 | `d4c3925` | Service skeleton, encrypted storage primitives |
| M2 | `1866a78` | Versioned keyring and DEK rewrapping |
| M3 | `ff0cbde` | Scoped clients, namespace isolation, audit and rate limiting |
| M4 | `34bca63` | REST metadata/write/generate/resolve and one-time intents |
| M5 | `bbace4b` | Admin login, TOTP replay defense, CSRF and management panel |
| M6 | `45f9e41` | Bound outbound fetch, pinned resolution and response redaction |
| M7 | `0871bcc` | MCP tools and CLI secret-resolution workflows |
| M8 | `e5b8546` | Hardening, documentation, regression and acceptance tests |

## Verification

- `sh docs/process/check-task.sh SV-20261015-01`: PASS, exit 0. The script confirmed task card/baseline, allowed-path scope, size limits (3,662 non-test lines / 48 files against 12,000 / 80), `git diff --check`, normal Go tests, race tests, and acceptance script.
- `go test -count=1 ./...`: PASS across all packages.
- `go test -count=1 -race ./...`: PASS across all test-bearing packages.
- `go vet ./...` and `go build ./...`: PASS.
- Regression inventory: 38 Go test functions across `cmd` and `internal` at final code state; several packages intentionally contain no direct tests and are exercised through API/integration tests.
- Reverse verification: temporarily disabled fetch response redaction; `TestFetchPinsIPDropsAuthAndRedacts` failed as expected (`response exposed injected value`). Temporarily injected the sentinel into secret-list metadata; `TestSentinelNeverListedOrAudited` failed as expected (`list exposed sentinel`). Both temporary faults were reverted, then full checks passed.
- Secret-output checks use only conspicuous fake values such as `SENTINEL-VALUE-7f3a9c`; no real credentials were used.

## Implementation decisions

- Prefer restrictive defaults: loopback listener, exact host allowlists, private/HTTP access disabled unless explicitly bound, no wildcard hosts, DNS resolution pinned for outbound requests, redirects not followed, and capped/redacted response handling.
- Metadata/list/admin pages never intentionally return secret plaintext; `/v1/resolve` is the explicit plaintext boundary, while fetch injects credentials only into a bound outbound request.
- Client tokens and one-time intent tokens are stored as SHA-256 digests; administrator passwords use Argon2id (3 iterations, 64 MiB, 2 lanes, 16-byte salt, 32-byte output) through the explicitly permitted `golang.org/x/crypto` dependency.
- Forwarded client IP headers are trusted only when the socket peer matches configured trusted proxy CIDRs. Admin sessions have idle/absolute expiry; login has TOTP replay defense, lockout and incremental delay.
- Provider verification uses the same constrained outbound engine; failed verification does not persist the proposed secret and does not expose provider response bodies.
- When `SWSV_PUBLIC_BASE_URL` is absent, one-time intent URLs remain relative rather than fabricating a public origin.

## Known limitations / operational notes

- This is a development deliverable only; it has not been deployed or exposed to a network.
- Review `docs/security.md`, `docs/providers.md`, `docs/api.md`, and `docs/ops.md` before deployment. In particular, production TLS/reverse-proxy policy, backups, key custody, monitoring, and recovery procedures must be finalized for the actual host environment.
- KEK rotation is an offline maintenance operation: stop the service before rotating so no process retains a stale in-memory keyring.
- The embedded admin panel is intentionally minimal; the v1 implementation prioritizes access control, secret-handling boundaries, and auditability over advanced UI features.
