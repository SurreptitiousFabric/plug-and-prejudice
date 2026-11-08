#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
renderer="$root/scripts/render-arch-pkgbuild.sh"

for command in bash; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "verify-arch-package-template: missing command: $command" >&2
    exit 1
  }
done

work=$(mktemp -d "${TMPDIR:-/tmp}/plug-prejudice-package.XXXXXX")
case $work in
  "${TMPDIR:-/tmp}"/plug-prejudice-package.*) ;;
  *) echo "verify-arch-package-template: unsafe temporary path" >&2; exit 1 ;;
esac
cleanup() {
  case $work in
    "${TMPDIR:-/tmp}"/plug-prejudice-package.*) rm -rf -- "$work" ;;
  esac
}
trap cleanup EXIT

version=1.2.3
source_url="https://github.com/SurreptitiousFabric/plug-and-prejudice/archive/refs/tags/v${version}.tar.gz"
source_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"$renderer" "$version" "$source_url" "$source_sha256" >"$work/PKGBUILD"

if grep -Eq '@(VERSION|SOURCE_URL|SOURCE_SHA256)@' "$work/PKGBUILD"; then
  echo 'verify-arch-package-template: unresolved template placeholder' >&2
  exit 1
fi
bash -n "$work/PKGBUILD"
if command -v makepkg >/dev/null 2>&1; then
  (cd "$work" && makepkg --printsrcinfo >.SRCINFO)
  sed 's/^[[:space:]]*//' "$work/.SRCINFO" >"$work/SRCINFO.normalized"

  for expected in \
    'pkgbase = plug-and-prejudice' \
    'pkgver = 1.2.3' \
    'arch = aarch64' \
    'arch = x86_64' \
    'depends = bubblewrap' \
    'depends = systemd'; do
    grep -Fxq "$expected" "$work/SRCINFO.normalized" || {
      echo "verify-arch-package-template: missing metadata: $expected" >&2
      exit 1
    }
  done

  grep -Fq "source = plug-and-prejudice-1.2.3.tar.gz::${source_url}" "$work/SRCINFO.normalized"
  grep -Fq "sha256sums = ${source_sha256}" "$work/SRCINFO.normalized"
fi
grep -Fq 'grammar_subset_python grammar_subset_javascript' "$work/PKGBUILD"
test "$(grep -Ec '^  go build .* -buildvcs=false' "$work/PKGBUILD")" = 2
grep -Fq 'GOFLAGS="-buildvcs=false ' "$work/PKGBUILD"
grep -Fq 'install -Dm755 plug-prejudice "${pkgdir}/usr/bin/plug-prejudice"' "$work/PKGBUILD"
grep -Fq 'install -Dm755 plug-prejudice-broker "${pkgdir}/usr/bin/plug-prejudice-broker"' "$work/PKGBUILD"

isolated_config="$root/packaging/arch/pacman-isolated.conf"
test "$(grep -Ec '^\[[^]]+\]$' "$isolated_config")" = 1
grep -Fxq '[options]' "$isolated_config"
grep -Fxq 'DownloadUser = root' "$isolated_config"
grep -Fxq 'SigLevel = Never' "$isolated_config"
if grep -Eq '^Server[[:space:]]*=|^Include[[:space:]]*=' "$isolated_config"; then
  echo 'verify-arch-package-template: isolated Pacman configuration enables a repository or include' >&2
  exit 1
fi

if "$renderer" v1.2.3 "$source_url" "$source_sha256" >/dev/null 2>&1 \
  || "$renderer" "$version" "http://example.invalid/source.tar.gz" "$source_sha256" >/dev/null 2>&1 \
  || "$renderer" "$version" "$source_url" AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >/dev/null 2>&1; then
  echo 'verify-arch-package-template: renderer accepted invalid release identity' >&2
  exit 1
fi

echo 'Arch package template renders pinned release inputs and safe fixed install paths'
