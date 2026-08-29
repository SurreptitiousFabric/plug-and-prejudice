#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$repo_root"

readonly parser_tags='grammar_subset grammar_subset_python grammar_subset_javascript'
expected=(
  "github.com/odvcencio/gotreesitter v0.51.0"
  "mvdan.cc/sh/v3 v3.13.1"
)
mapfile -t actual < <(
  go list -tags "$parser_tags" -deps \
    -f '{{with .Module}}{{if and (not .Main) .Path}}{{.Path}} {{.Version}}{{end}}{{end}}' \
    ./cmd/plug-prejudice ./cmd/plug-prejudice-broker | sort -u
)

if (( ${#actual[@]} != ${#expected[@]} )); then
  echo "production dependency set changed; review go.mod, licenses, notices, and docs/dependencies.md" >&2
  printf 'expected: %s\n' "${expected[@]}" >&2
  printf 'actual:   %s\n' "${actual[@]}" >&2
  exit 1
fi

for index in "${!expected[@]}"; do
  if [[ ${actual[$index]} != "${expected[$index]}" ]]; then
    echo "production dependency set changed; review go.mod, licenses, notices, and docs/dependencies.md" >&2
    printf 'expected: %s\n' "${expected[@]}" >&2
    printf 'actual:   %s\n' "${actual[@]}" >&2
    exit 1
  fi
done

for required_notice in \
	'github.com/odvcencio/gotreesitter' \
	'0.51.0' \
	'MIT License' \
	'Copyright (c) 2026 Oscar Villavicencio' \
	'mvdan.cc/sh/v3' \
  '3.13.1' \
  'BSD 3-Clause' \
  'Copyright (c) 2016, Daniel Martí'; do
  if ! grep -Fq -- "$required_notice" THIRD_PARTY_NOTICES.md; then
    echo "THIRD_PARTY_NOTICES.md is missing required text: $required_notice" >&2
    exit 1
  fi
done

go mod verify
echo "Production Go dependency set and third-party notice are current"
