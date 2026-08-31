#!/usr/bin/env bash
set -euo pipefail

workflow_root="${1:-.github/workflows}"

if [[ ! -d "$workflow_root" ]]; then
  echo "workflow directory is missing: $workflow_root" >&2
  exit 1
fi

mapfile -d '' workflows < <(find "$workflow_root" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 | sort -z)
if (( ${#workflows[@]} == 0 )); then
  echo "no GitHub Actions workflows found in $workflow_root" >&2
  exit 1
fi

failed=0
fail() {
  echo "CI policy: $*" >&2
  failed=1
}

for workflow in "${workflows[@]}"; do
  label="${workflow#"$workflow_root"/}"

  permission_block="$(awk '
    /^permissions:[[:space:]]*$/ { in_permissions=1; next }
    in_permissions && /^  [A-Za-z0-9_-]+:[[:space:]]*/ { print; next }
    in_permissions { exit }
  ' "$workflow")"
  if [[ "$permission_block" != '  contents: read' ]]; then
    fail "$label must grant exactly contents: read at top level"
  fi
  nested_permissions=$(grep -Ec '^    permissions:[[:space:]]*$' "$workflow" || true)
  write_permissions=$(grep -Ec '^[[:space:]]+[A-Za-z0-9_-]+:[[:space:]]*(write|write-all)[[:space:]]*$|^permissions:[[:space:]]*(write|write-all)[[:space:]]*$' "$workflow" || true)
  if [[ $label == release.yml ]]; then
    if (( nested_permissions != 1 || write_permissions != 3 )) \
      || ! grep -Fq "tags: ['v*.*.*']" "$workflow" \
      || ! grep -Fq '      contents: write' "$workflow" \
      || ! grep -Fq '      id-token: write' "$workflow" \
      || ! grep -Fq '      attestations: write' "$workflow"; then
      fail "$label must confine its exact three write grants to the tag-only publish job"
    fi
  elif (( nested_permissions != 0 || write_permissions != 0 )); then
    fail "$label grants or overrides job permissions"
  fi
  if grep -Eq '^[[:space:]]*(pull_request_target|workflow_run|repository_dispatch|issue_comment):' "$workflow"; then
    fail "$label uses a privileged or indirect trigger"
  fi
  if grep -Eq '\$\{\{[[:space:]]*secrets\.|^[[:space:]]*secrets:' "$workflow"; then
    fail "$label references secrets"
  fi
  if grep -Eq '^[[:space:]]*continue-on-error:[[:space:]]*true[[:space:]]*$' "$workflow"; then
    fail "$label hides a failing step or job"
  fi
  if grep -Eq 'persist-credentials:[[:space:]]*true' "$workflow"; then
    fail "$label persists checkout credentials"
  fi

  checkout_count="$(grep -Ec '^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*actions/checkout@' "$workflow" || true)"
  disabled_credentials_count="$(grep -Ec '^[[:space:]]*persist-credentials:[[:space:]]*false[[:space:]]*$' "$workflow" || true)"
  if (( checkout_count != disabled_credentials_count )); then
    fail "$label must set persist-credentials: false for every checkout"
  fi

  while IFS= read -r line; do
    reference="${line#*uses:}"
    reference="${reference%%#*}"
    reference="${reference//[[:space:]]/}"
    if [[ "$reference" == ./* ]]; then
      continue
    fi
    if [[ "$reference" =~ ^docker://[^@]+@sha256:[0-9a-f]{64}$ ]]; then
      continue
    fi
    if [[ ! "$reference" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$ ]]; then
      fail "$label has an action that is not pinned to a full commit SHA: $reference"
    fi
  done < <(grep -E '^[[:space:]]*(-[[:space:]]+)?uses:' "$workflow" || true)

  while IFS= read -r job; do
    fail "$label job $job has no timeout-minutes"
  done < <(awk '
    /^jobs:[[:space:]]*$/ { in_jobs=1; next }
    in_jobs && /^[^[:space:]]/ { in_jobs=0 }
    in_jobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
      if (job != "" && !timeout) print job
      job=$1
      sub(/:$/, "", job)
      timeout=0
      next
    }
    in_jobs && job != "" && /^    timeout-minutes:[[:space:]]*[1-9][0-9]*[[:space:]]*$/ { timeout=1 }
    END { if (job != "" && !timeout) print job }
  ' "$workflow")
done

if (( failed != 0 )); then
  exit 1
fi

echo "GitHub Actions workflows satisfy the local least-privilege policy"
