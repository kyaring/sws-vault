#!/usr/bin/env bash
set -euo pipefail
APPLY=0
for arg in "$@"; do case "$arg" in --apply) APPLY=1;; *) echo "usage: $0 [--apply]" >&2; exit 2;; esac; done
ROOT=${ROOT:-}
root_path() { if [[ -n "$ROOT" ]]; then printf '%s%s' "${ROOT%/}" "$1"; else printf '%s' "$1"; fi; }
db=$(root_path /var/lib/sws-vault/vault.db)
outdir=$(root_path /var/backups/sws-vault)
stamp=$(date -u +%Y%m%d-%H%M%S)
out="$outdir/vault-$stamp.sqlite3"
if (( ! APPLY )); then printf 'DRY-RUN: SQLite consistent backup %s -> %s\n' "$db" "$out"; printf 'DRY-RUN: retain latest 14 backups; master key is excluded.\n'; exit 0; fi
[[ -f "$db" ]] || { echo "database not found: $db" >&2; exit 1; }
command -v python3 >/dev/null || { echo 'python3 is required for SQLite online backup' >&2; exit 1; }
install -d -m 0700 "$outdir"
tmp="$out.tmp.$$"
trap 'rm -f "$tmp"' EXIT
python3 - "$db" "$tmp" <<'PY'
import os, sqlite3, sys
src, dst = sys.argv[1:]
with sqlite3.connect(f"file:{src}?mode=ro", uri=True) as source:
    with sqlite3.connect(dst) as target:
        source.backup(target)
os.chmod(dst, 0o600)
PY
mv "$tmp" "$out"
find "$outdir" -maxdepth 1 -type f -name 'vault-*.sqlite3' -printf '%T@ %p\n' | sort -nr | awk 'NR>14 {sub(/^[^ ]+ /, ""); print}' | while IFS= read -r old; do rm -f -- "$old"; done
printf 'Database backup created: %s (mode 0600). Master key was not copied; maintain it separately offline.\n' "$out"
