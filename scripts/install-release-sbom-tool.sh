#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )); then
  echo 'usage: install-release-sbom-tool.sh EMPTY_DESTINATION' >&2
  exit 2
fi
destination=$1
[[ ! -e $destination && ! -L $destination ]] || { echo 'destination already exists' >&2; exit 2; }

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck disable=SC1091 -- exact reviewed repository file.
source "$root/packaging/release-tools.env"
case $(uname -m) in
  x86_64)
    release_arch=amd64
    expected_sha256=$CYCLONEDX_GOMOD_LINUX_AMD64_SHA256
    ;;
  aarch64|arm64)
    release_arch=arm64
    expected_sha256=$CYCLONEDX_GOMOD_LINUX_ARM64_SHA256
    ;;
  *) echo 'unsupported release-tool architecture' >&2; exit 1 ;;
esac

for command in curl mkdir mktemp sha256sum tar; do
  command -v "$command" >/dev/null 2>&1 || { echo "missing command: $command" >&2; exit 1; }
done
archive=$(mktemp "${TMPDIR:-/tmp}/cyclonedx-gomod.XXXXXX")
case $archive in "${TMPDIR:-/tmp}"/cyclonedx-gomod.*) ;; *) exit 1 ;; esac
trap 'case $archive in "${TMPDIR:-/tmp}"/cyclonedx-gomod.*) rm -f -- "$archive" ;; esac' EXIT
url="https://github.com/CycloneDX/cyclonedx-gomod/releases/download/v${CYCLONEDX_GOMOD_VERSION}/cyclonedx-gomod_${CYCLONEDX_GOMOD_VERSION}_linux_${release_arch}.tar.gz"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error "$url" --output "$archive"
echo "$expected_sha256  $archive" | sha256sum --check --strict >/dev/null
mkdir -- "$destination"
destination=$(cd -- "$destination" && pwd -P)
tar -xzf "$archive" -C "$destination" cyclonedx-gomod
[[ -f $destination/cyclonedx-gomod && ! -L $destination/cyclonedx-gomod ]] || { echo 'tool archive did not produce a regular executable' >&2; exit 1; }
chmod 0500 "$destination/cyclonedx-gomod"
version_output=$("$destination/cyclonedx-gomod" version)
grep -Eq "^Version:[[:space:]]+v${CYCLONEDX_GOMOD_VERSION}$" <<<"$version_output" || { echo 'tool reports an unexpected version' >&2; exit 1; }
grep -Eq "^Arch:[[:space:]]+${release_arch}$" <<<"$version_output" || { echo 'tool reports an unexpected architecture' >&2; exit 1; }
printf '%s\n' "$destination"
