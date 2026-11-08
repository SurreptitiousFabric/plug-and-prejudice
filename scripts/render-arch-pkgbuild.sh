#!/usr/bin/env bash
set -euo pipefail

if (( $# != 3 )); then
  echo 'usage: render-arch-pkgbuild.sh VERSION SOURCE_URL SOURCE_SHA256' >&2
  exit 2
fi
version=$1
source_url=$2
source_sha256=$3
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'version must be X.Y.Z' >&2; exit 2; }
[[ $source_url == https://* ]] || { echo 'source URL must use HTTPS' >&2; exit 2; }
[[ $source_sha256 =~ ^[0-9a-f]{64}$ ]] || { echo 'source SHA-256 must be 64 lowercase hexadecimal characters' >&2; exit 2; }

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
sed -e "s|@VERSION@|${version}|g" \
  -e "s|@SOURCE_URL@|${source_url}|g" \
  -e "s|@SOURCE_SHA256@|${source_sha256}|g" \
  "$root/packaging/arch/PKGBUILD.in"
