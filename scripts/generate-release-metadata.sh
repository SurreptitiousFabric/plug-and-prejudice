#!/usr/bin/env bash
set -euo pipefail

if (( $# != 2 )); then
  echo 'usage: generate-release-metadata.sh VERSION DIST_DIRECTORY' >&2
  exit 2
fi

version=$1
dist=$2
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'version must be X.Y.Z' >&2; exit 2; }
[[ -d $dist && ! -L $dist ]] || { echo 'dist directory must be a real directory' >&2; exit 2; }
dist=$(cd -- "$dist" && pwd -P)

for command in cyclonedx-gomod file go readelf sha256sum; do
  command -v "$command" >/dev/null 2>&1 || { echo "missing command: $command" >&2; exit 1; }
done

artifacts=()
for arch in amd64 arm64; do
  case $arch in
    amd64) machine='Advanced Micro Devices X86-64' ;;
    arm64) machine='AArch64' ;;
  esac
  for name in plug-prejudice plug-prejudice-broker; do
    artifact="$dist/${name}-linux-${arch}"
    [[ -f $artifact && ! -L $artifact && -x $artifact ]] || {
      echo "missing regular executable: ${artifact##*/}" >&2
      exit 1
    }
    file -b "$artifact" | grep -Fq 'ELF 64-bit' || { echo "not a 64-bit ELF: ${artifact##*/}" >&2; exit 1; }
    readelf -h "$artifact" | grep -Fq "Machine:                           $machine" || {
      echo "wrong architecture: ${artifact##*/}" >&2
      exit 1
    }
    if readelf --program-headers "$artifact" | grep -q INTERP \
      || readelf --dynamic "$artifact" 2>/dev/null | grep -q '(NEEDED)'; then
      echo "not a static executable: ${artifact##*/}" >&2
      exit 1
    fi
    artifacts+=("$artifact")
  done
done

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
sbom="$dist/plug-and-prejudice-${version}.cdx.json"
(cd "$root" && cyclonedx-gomod \
  mod -json -notimestamp -noserial -output "$sbom" .)
[[ -s $sbom && ! -L $sbom ]] || { echo 'SBOM was not produced as a regular file' >&2; exit 1; }
sboms=("$sbom")
for artifact in "${artifacts[@]}"; do
  binary_sbom="$artifact.cdx.json"
  cyclonedx-gomod bin -json -notimestamp -noserial -version "v$version" -output "$binary_sbom" "$artifact"
  [[ -s $binary_sbom && ! -L $binary_sbom ]] || { echo "binary SBOM was not produced: ${binary_sbom##*/}" >&2; exit 1; }
  sboms+=("$binary_sbom")
done

checksums="$dist/plug-and-prejudice-${version}.sha256"
(
  cd "$dist"
  names=()
  for artifact in "${artifacts[@]}" "${sboms[@]}"; do names+=("${artifact##*/}"); done
  LC_ALL=C sha256sum "${names[@]}"
) >"$checksums"

echo "Generated CycloneDX SBOM and checksum manifest in $dist"
