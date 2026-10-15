#!/usr/bin/env bash
set -euo pipefail
APPLY=0
for arg in "$@"; do case "$arg" in --apply) APPLY=1;; *) echo "usage: $0 [--apply]" >&2; exit 2;; esac; done
ROOT=${ROOT:-}
root_path() { if [[ -n "$ROOT" ]]; then printf '%s%s' "${ROOT%/}" "$1"; else printf '%s' "$1"; fi; }
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
src=${SWSV_BINARY:-$repo/bin/swsvault}
bin=$(root_path /usr/local/bin/swsvault)
prev=$(root_path /usr/local/bin/swsvault.prev)
data=$(root_path /var/lib/sws-vault)
conf=$(root_path /etc/sws-vault)
key="$conf/master.key"
unit=$(root_path /etc/systemd/system/sws-vault.service)
if (( ! APPLY )); then
  printf 'DRY-RUN: create system user sws-vault (skipped for ROOT sandbox)\n'
  printf 'DRY-RUN: create %s and %s with restrictive permissions\n' "$data" "$conf"
  printf 'DRY-RUN: install %s -> %s (existing binary saved as .prev)\n' "$src" "$bin"
  printf 'DRY-RUN: install deploy/sws-vault.service -> %s; do not enable/start automatically\n' "$unit"
  printf 'DRY-RUN: create master key only if absent; never print or overwrite it\n'
  printf 'FIREWALL NOTE: no firewall changes made; see docs/ops.md for the 192.168.20.0/24 nft rule.\n'
  exit 0
fi
[[ -x "$src" ]] || { echo "missing executable build: $src (run make build first)" >&2; exit 1; }
if [[ -z "$ROOT" ]]; then
  [[ $EUID -eq 0 ]] || { echo 'must run as root' >&2; exit 1; }
  if ! getent group sws-vault >/dev/null; then groupadd --system sws-vault; fi
  if ! getent passwd sws-vault >/dev/null; then useradd --system --gid sws-vault --home-dir /var/lib/sws-vault --shell /usr/sbin/nologin sws-vault; fi
fi
install -d -m 0700 "$data" "$conf"
install -d -m 0755 "$(dirname "$bin")" "$(dirname "$unit")"
if [[ -f "$bin" ]] && ! cmp -s "$src" "$bin"; then cp -p "$bin" "$prev"; fi
install -m 0755 "$src" "$bin"
install -m 0644 "$repo/deploy/sws-vault.service" "$unit"
if [[ ! -e "$key" ]]; then
  SWSV_DATA_DIR="$data" SWSV_DB_PATH="$data/vault.db" SWSV_MASTER_KEY_PATH="$key" "$bin" keygen --out "$key"
else
  echo 'Existing master key preserved.'
fi
chmod 0600 "$key"
if [[ -z "$ROOT" ]]; then chown -R sws-vault:sws-vault "$data" "$conf"; fi
printf 'Installed. Service is NOT enabled or started.\n'
printf 'Panel: http://192.168.20.132:9531/admin (direct LAN access; no tunnel).\n'
printf 'Firewall unchanged: allow only 192.168.20.0/24 per docs/ops.md if/when approved.\n'
