#!/usr/bin/env bash
set -euo pipefail
APPLY=0
for arg in "$@"; do case "$arg" in --apply) APPLY=1;; *) echo "usage: $0 [--apply]" >&2; exit 2;; esac; done
ROOT=${ROOT:-}
root_path() { if [[ -n "$ROOT" ]]; then printf '%s%s' "${ROOT%/}" "$1"; else printf '%s' "$1"; fi; }
bin=$(root_path /usr/local/bin/swsvault)
prev=$(root_path /usr/local/bin/swsvault.prev)
if (( ! APPLY )); then printf 'DRY-RUN: restore %s -> %s, restart service, verify /healthz and version.\n' "$prev" "$bin"; exit 0; fi
[[ -x "$prev" ]] || { echo "rollback binary not found: $prev" >&2; exit 1; }
[[ -x "$bin" ]] && cp -p "$bin" "${bin}.failed"
install -m 0755 "$prev" "$bin"
if [[ -z "$ROOT" ]]; then
  systemctl restart sws-vault
  curl --fail --silent --show-error http://192.168.20.132:9531/healthz
  printf '\nRolled back binary version: '; "$bin" version
else
  printf 'ROOT sandbox: file rollback complete; service restart and HTTP health check skipped.\n'
fi
