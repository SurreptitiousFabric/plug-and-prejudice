#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/plug-prejudice-release.XXXXXX")
case $work in "${TMPDIR:-/tmp}"/plug-prejudice-release.*) ;; *) exit 1 ;; esac
trap 'case $work in "${TMPDIR:-/tmp}"/plug-prejudice-release.*) rm -rf -- "$work" ;; esac' EXIT

version=0.0.1
tags='netgo osusergo grammar_subset grammar_subset_python grammar_subset_javascript'
ldflags="-X github.com/SurreptitiousFabric/plug-and-prejudice/internal/buildinfo.Version=$version"
for arch in amd64 arm64; do
  for name in plug-prejudice plug-prejudice-broker; do
    command_path=./cmd/$name
    (cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch \
      go build -mod=readonly -buildvcs=false -trimpath -tags "$tags" -ldflags "$ldflags" \
      -o "$work/$name-linux-$arch" "$command_path")
  done
done

tool_dir=$("$root/scripts/install-release-sbom-tool.sh" "$work/tool")
PATH="$tool_dir:$PATH" "$root/scripts/generate-release-metadata.sh" "$version" "$work"
(cd "$work" && sha256sum --check "plug-and-prejudice-$version.sha256")
test "$(find "$work" -maxdepth 1 -type f -name '*.cdx.json' | wc -l)" = 5
test "$(wc -l <"$work/plug-and-prejudice-$version.sha256")" = 9
for sbom in "$work"/*.cdx.json; do
  grep -Fq '"bomFormat": "CycloneDX"' "$sbom"
  grep -Fq '"specVersion": "1.6"' "$sbom"
done

case $(uname -m) in x86_64) native=amd64 ;; aarch64|arm64) native=arm64 ;; *) exit 1 ;; esac
for name in plug-prejudice plug-prejudice-broker; do
  "$work/$name-linux-$native" --version | grep -Fq "\"reviewerVersion\":\"$version\""
done

echo 'Release metadata binds four artifacts, five CycloneDX SBOMs, and one checksum manifest'
