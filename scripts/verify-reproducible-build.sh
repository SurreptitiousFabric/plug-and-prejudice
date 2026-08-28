#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

for command in go readelf sha256sum cmp mktemp; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "verify-reproducible-build: missing command: $command" >&2
    exit 1
  }
done

work=$(mktemp -d "${TMPDIR:-/tmp}/plug-prejudice-build.XXXXXX")
case $work in
  "${TMPDIR:-/tmp}"/plug-prejudice-build.*) ;;
  *) echo "verify-reproducible-build: unsafe temporary path" >&2; exit 1 ;;
esac
cleanup() {
  case $work in
    "${TMPDIR:-/tmp}"/plug-prejudice-build.*) rm -rf -- "$work" ;;
  esac
}
trap cleanup EXIT

mkdir -p "$work/first" "$work/second"
readonly packages=(plug-prejudice plug-prejudice-broker)
readonly parser_tags='netgo osusergo grammar_subset grammar_subset_python grammar_subset_javascript'
for binary in "${packages[@]}"; do
  CGO_ENABLED=0 go build -tags "$parser_tags" -buildvcs=false -trimpath -o "$work/first/$binary" "./cmd/$binary"
  CGO_ENABLED=0 go build -tags "$parser_tags" -buildvcs=false -trimpath -o "$work/second/$binary" "./cmd/$binary"
  if ! cmp -s -- "$work/first/$binary" "$work/second/$binary"; then
    echo "verify-reproducible-build: $binary differs between identical builds" >&2
    sha256sum "$work/first/$binary" "$work/second/$binary" >&2
    exit 1
  fi

  program_headers=$(readelf --program-headers "$work/first/$binary")
  if grep -q 'INTERP' <<<"$program_headers"; then
    echo "verify-reproducible-build: $binary has a runtime interpreter" >&2
    exit 1
  fi
  dynamic_section=$(readelf --dynamic "$work/first/$binary" 2>/dev/null)
  if grep -q '(NEEDED)' <<<"$dynamic_section"; then
    echo "verify-reproducible-build: $binary imports a shared library" >&2
    exit 1
  fi
done

case $(go env GOARCH) in
  arm64) expected_machine='AArch64' ;;
  amd64) expected_machine='Advanced Micro Devices X86-64' ;;
  *) echo "verify-reproducible-build: unsupported GOARCH $(go env GOARCH)" >&2; exit 1 ;;
esac
for binary in "${packages[@]}"; do
  machine=$(readelf --file-header "$work/first/$binary" | sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p')
  if [[ $machine != "$expected_machine" ]]; then
    echo "verify-reproducible-build: $binary machine '$machine', expected '$expected_machine'" >&2
    exit 1
  fi
  printf '%s  %s (%s)\n' "$(sha256sum "$work/first/$binary" | cut -d' ' -f1)" "$binary" "$machine"
done

echo "Native static builds are byte-reproducible in this checkout"
