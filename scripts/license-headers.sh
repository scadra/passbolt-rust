#!/usr/bin/env bash
# Check (default) or add (--fix) the Passbolt license header on every .rs file.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
header="$root/scripts/license-header.txt"
marker="// Passbolt ~ Open source password manager for teams"
fix=false
[[ "${1:-}" == "--fix" ]] && fix=true

missing=0
while IFS= read -r -d '' file; do
  if [[ "$(head -n 1 "$file")" == "$marker" ]]; then
    continue
  fi
  if $fix; then
    { cat "$header"; echo; cat "$file"; } > "$file.tmp" && mv "$file.tmp" "$file"
    echo "added: ${file#"$root"/}"
  else
    echo "missing header: ${file#"$root"/}"
    missing=$((missing + 1))
  fi
done < <(find "$root" -name '*.rs' -not -path '*/target/*' -print0)

if ! $fix && (( missing > 0 )); then
  echo "$missing file(s) without license header. Run scripts/license-headers.sh --fix" >&2
  exit 1
fi
