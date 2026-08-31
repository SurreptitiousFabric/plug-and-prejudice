#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$repo_root"

go mod verify
module_dir=$(go list -m -f '{{.Dir}}' golang.org/x/sys)
license_file="$module_dir/LICENSE"
identity='golang.org/x/sys v0.47.0'

scripts/verify-third-party-license-block.sh \
  THIRD_PARTY_NOTICES.md "$identity" "$license_file"

tampered=$(mktemp)
trap 'rm -f -- "$tampered"' EXIT
sed '/^   \* Redistributions of source code must retain the above copyright$/d' \
  THIRD_PARTY_NOTICES.md >"$tampered"
if scripts/verify-third-party-license-block.sh \
  "$tampered" "$identity" "$license_file" >/dev/null 2>&1; then
  echo "licence verification accepted a notice missing one condition" >&2
  exit 1
fi

echo "Verbatim x/sys licence block matches; one-condition deletion is rejected"
