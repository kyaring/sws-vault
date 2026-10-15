# SWS Vault S-6 test deployment runbook

This runbook describes a **test-only, LAN-only** deployment on `wjy5010u`. It is not a production deployment recipe. The test service binds only to `192.168.20.132:9531`; it must never bind to `0.0.0.0:9531` or `[::]:9531` because this node has public IPv6. Do not add a reverse proxy or expose this service to the public internet. HTTP is plaintext, so use fake/test credentials only until TLS and the proxy trust boundary are reviewed.

## Network and firewall

The listener is `192.168.20.132:9531`; `SWSV_PUBLIC_BASE_URL` is `http://192.168.20.132:9531`. The admin panel is opened directly from a LAN browser at `http://192.168.20.132:9531/admin`—no SSH tunnel. `install.sh` never changes the firewall and never enables or starts the unit.

The node's nftables input chain defaults to drop. After separate approval, allow only the LAN subnet. First inspect the actual table/chain names (`nft list ruleset`) and confirm `inet filter input` exists. Runtime rule:

```sh
sudo nft add rule inet filter input ip saddr 192.168.20.0/24 tcp dport 9531 accept comment "sws-vault-test"
sudo nft -a list chain inet filter input
```

Persist the same rule in `/etc/nftables.conf` in the `inet filter input` chain **before** the final drop/reject rule, then validate and apply with `sudo nft -c -f /etc/nftables.conf` followed by `sudo nft -f /etc/nftables.conf`. Do not replace the existing ruleset wholesale without review. Confirm from a LAN client that TCP/9531 is reachable and from outside the LAN that it is not.

Rollback: identify the rule handle from `nft -a list chain inet filter input`, then run `sudo nft delete rule inet filter input handle HANDLE`. Remove the matching `ip saddr 192.168.20.0/24 tcp dport 9531 accept comment "sws-vault-test"` line from `/etc/nftables.conf`, validate with `nft -c -f`, and reload the file. Substitute the actual table/chain if the host's ruleset differs. The install scripts do not perform any of these firewall actions.

## Build and dry-run

From the repository checkout, run `make build` and inspect `./bin/swsvault version`. All four scripts default to dry-run:

```sh
./deploy/install.sh
./deploy/backup.sh
./deploy/upgrade.sh
./deploy/rollback.sh
```

Only after separate approval use `--apply`. `ROOT=/temporary/fake-root` redirects filesystem paths into a test tree; it skips OS user management, systemd operations, and network health checks. Never use `--apply` without `ROOT` during package testing. The install script installs `/usr/local/bin/swsvault`, saves a differing previous binary as `.prev`, installs the service unit, and creates a key only if absent. Existing `master.key` is never replaced. The service is not enabled or started automatically. The installer only prints the firewall reminder.

## First-time installation and admin enrollment

1. Build and review the artifacts. Run `install.sh --apply` only after the host operator approves the real paths and account creation.
2. Review ownership and modes: `/etc/sws-vault/master.key` must be owned by `sws-vault:sws-vault` and mode `0600`; `/var/lib/sws-vault` must be private to the service account.
3. The installer intentionally does not enable or start the unit. After the network rule is approved, run `sudo systemctl daemon-reload`, then an operator may run `sudo systemctl enable --now sws-vault` and check `systemctl status sws-vault` and `journalctl -u sws-vault`.
4. Initialize the admin interactively from a trusted terminal as the service account, using the service's environment paths: `sudo -u sws-vault env SWSV_DATA_DIR=/var/lib/sws-vault SWSV_DB_PATH=/var/lib/sws-vault/vault.db SWSV_MASTER_KEY_PATH=/etc/sws-vault/master.key /usr/local/bin/swsvault admin init`. Store the displayed TOTP enrollment URI securely and do not paste it into logs or tickets. Choose a unique test password and enroll TOTP.
5. Open `http://192.168.20.132:9531/admin` directly from the LAN. HTTP is not encrypted; do not enter production credentials or use this test deployment over an untrusted network.
6. Verify `curl --fail http://192.168.20.132:9531/healthz`, inspect service logs, and run a test secret create/resolve/list workflow. Confirm list/panel/log/audit outputs do not reveal secret values. Resolve intentionally returns plaintext `value` and bound `username`; keep that endpoint's scope and binding gate restrictive.

## Backup

`backup.sh` uses Python's SQLite online backup API to create a consistent snapshot at `/var/backups/sws-vault/vault-YYYYMMDD-HHMMSS.sqlite3`, mode `0600`, retaining the latest 14 snapshots. It does not copy the master key. Back up key material separately through an approved offline custody process; never place it beside the database backup. Run a restore drill in an isolated directory before relying on backups.

```sh
./deploy/backup.sh                 # dry-run
./deploy/backup.sh --apply         # approved host operation only
```

## Upgrade and rollback

Build the new binary and verify its version before use. `upgrade.sh` defaults to dry-run; with approval, `upgrade.sh --apply` first makes a database backup, preserves the current binary as `.prev`, installs the new binary, restarts the service, and checks `/healthz` plus the installed binary's `version` output. Confirm the running service's startup time and logs as part of the operator check. If health checks fail, run `rollback.sh --apply` to restore `.prev`, restart, and check health/version again. `ROOT=/temporary/fake-root` performs file operations only and skips service/network checks.

```sh
./deploy/upgrade.sh
./deploy/rollback.sh
```

## Uninstall

Stop and disable the service only after confirming it is no longer needed. Remove the unit and executable through a separately reviewed change. Do not automatically delete `/var/lib/sws-vault`, `/etc/sws-vault/master.key`, or backups: preserve them until an authorized retention decision and successful recovery/export. Destroy key material only after confirming that all required data has been retired.

## Security and recovery notes

- Keep the master key separate from database backups, mode `0600`; never print it or place it in the repository.
- `resolve` returns plaintext `value` **and** bound `username`, only when the client has `resolve` scope and the binding allows resolve (and any client allowlist matches). It is an explicit plaintext boundary.
- This LAN test deployment has no TLS. Use fake credentials only; do not configure reverse proxies or public access.
- If a key is lost or corrupted, stop the service and restore the matching key versions and database from separately protected copies. Do not generate a replacement key for an existing database; old ciphertext will not decrypt.
- When a reverse proxy is introduced in a later approved design, configure `SWSV_TRUSTED_PROXY_CIDRS` to exact proxy peer CIDRs. Without it, forwarding headers are ignored and one WARN is emitted per process.
