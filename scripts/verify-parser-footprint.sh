#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$root"
work=$(mktemp -d "${TMPDIR:-/tmp}/plug-prejudice-parser-size.XXXXXX")
cleanup() {
  case $work in "${TMPDIR:-/tmp}"/plug-prejudice-parser-size.*) rm -rf -- "$work" ;; esac
}
trap cleanup EXIT

readonly tags='grammar_subset grammar_subset_python grammar_subset_javascript'
readonly max_scanner_bytes=$((20 << 20))
for arch in arm64 amd64; do
  output="$work/plug-prejudice-$arch"
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -mod=readonly -trimpath -tags "$tags" -o "$output" ./cmd/plug-prejudice
  size=$(stat -c '%s' "$output")
  if (( size > max_scanner_bytes )); then
    echo "selective Python/JavaScript scanner for $arch is $size bytes, above $max_scanner_bytes" >&2
    exit 1
  fi
  printf '%s %s bytes\n' "$arch" "$size"
done

echo 'Selective Python/JavaScript parser footprint is within the reviewed ceiling'
