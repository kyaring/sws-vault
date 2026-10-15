# Operations draft (not deployed)

This document is a deployment proposal only. This development task does not create systemd units, modify `/etc` or `/var/lib`, open network ports, or install the binary.

## Runtime layout

- Run one dedicated service account with write access only to the chosen SWS Vault data directory.
- Keep `master.key` and versioned `master.key.vN` files mode 0600. Store them separately from the SQLite database and do not place either in the repository, web root, or backup bundle together.
- Keep the listener on `127.0.0.1:9531` unless a reviewed deployment card specifies another private binding.
- Argon2id password hashing and provider pre-save verification are implemented. Do not deploy until the full acceptance gate passes and the actual host’s TLS/reverse-proxy, backup, key-custody, monitoring, and recovery procedures have been reviewed.

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
- If deployed behind a reverse proxy, you must configure `SWSV_TRUSTED_PROXY_CIDRS` to the proxy peer CIDRs. Never trust arbitrary caller-supplied forwarding headers. Without this setting, `X-Forwarded-For` is ignored and the socket peer IP (often the proxy) is used for login lockout; this can lock out the administrator. The service emits one WARN per process if it receives this header without trusted proxy CIDRs.
- Preserve `Cache-Control: no-store` on resolve responses; do not cache `/v1`, `/admin`, `/mcp`, or `/i` responses.
- Do not log authorization headers, request bodies, form bodies, or response bodies. Access logs should omit query strings on one-time intent links because the path token is a bearer capability.
- Do not enable public exposure until the full acceptance gate passes and the actual host TLS/reverse-proxy, backup, key-custody, monitoring, and recovery procedures have been reviewed.

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

## Build and version

Build the executable with `make build`; the target injects the current 12-character Git commit into `swsvault version`. Verify with `./bin/swsvault version` and `git rev-parse --short=12 HEAD`.

## Key rotation maintenance

`swsvault admin rotate-kek` must be run with the service stopped so no process continues using an in-memory keyring from before rotation. It writes a new versioned key file with exclusive creation and mode 0600, then transactionally rewraps each DEK, re-encrypts the secret with the new key-version AAD, and recalculates the fingerprint. If rotation fails, keep all key versions and restore service only after a read-only resolve smoke test confirms old values remain readable.
