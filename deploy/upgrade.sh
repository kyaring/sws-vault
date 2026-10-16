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
if (( ! APPLY )); then printf 'DRY-RUN: backup database, preserve current binary as .prev, install %s, restart, verify /healthz and version.\n' "$src"; exit 0; fi
[[ -x "$src" ]] || { echo "missing executable build: $src" >&2; exit 1; }
"$(dirname "${BASH_SOURCE[0]}")/backup.sh" --apply
[[ -x "$bin" ]] && cp -p "$bin" "$prev"
install -m 0755 "$src" "$bin"
if [[ -z "$ROOT" ]]; then
  systemctl restart sws-vault
  healthz=http://192.168.20.132:9531/healthz
  ready=0
  for _ in $(seq 1 15); do
    if curl --fail --silent --show-error --output /dev/null "$healthz"; then ready=1; break; fi
    sleep 1
  done
  if (( ! ready )); then
    echo "healthz 在 15 秒内没有就绪：$healthz" >&2
    exit 1
  fi
  curl --fail --silent --show-error "$healthz"
  printf '\nInstalled binary version: '; "$bin" version
  systemctl --no-pager --full status sws-vault | sed -n '1,12p'
  journalctl -u sws-vault -n 20 --no-pager
else
  printf 'ROOT sandbox: file upgrade complete; service restart and HTTP health check skipped.\n'
fi
