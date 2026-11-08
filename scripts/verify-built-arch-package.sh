#!/usr/bin/env bash
set -euo pipefail

if (( $# != 2 )); then
  echo 'usage: verify-built-arch-package.sh VERSION PACKAGE_FILE' >&2
  exit 2
fi
version=$1
package=$2
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'version must be X.Y.Z' >&2; exit 2; }
[[ -f $package && ! -L $package ]] || { echo 'package must be a regular file' >&2; exit 2; }
package=$(realpath --canonicalize-existing -- "$package")

for command in bsdtar pacman readelf sort; do
  command -v "$command" >/dev/null 2>&1 || { echo "missing command: $command" >&2; exit 1; }
done

identity=$(pacman -Qp -- "$package")
[[ $identity == "plug-and-prejudice ${version}-1" ]] || {
  echo "unexpected package identity: $identity" >&2
  exit 1
}

pkginfo=$(bsdtar -xOf "$package" .PKGINFO)
arch=$(sed -n 's/^arch = //p' <<<"$pkginfo")
case $arch in aarch64|x86_64) ;; *) echo "unsupported package architecture: $arch" >&2; exit 1 ;; esac

expected=$(printf '%s\n' \
  /usr/ \
  /usr/bin/ \
  /usr/bin/plug-prejudice \
  /usr/bin/plug-prejudice-broker \
  /usr/share/ \
  /usr/share/doc/ \
  /usr/share/doc/plug-and-prejudice/ \
  /usr/share/doc/plug-and-prejudice/THIRD_PARTY_NOTICES.md \
  /usr/share/licenses/ \
  /usr/share/licenses/plug-and-prejudice/ \
  /usr/share/licenses/plug-and-prejudice/LICENSE | sort)
actual=$(pacman -Qlp -- "$package" | sed 's/^[^ ]* //' | sort)
[[ $actual == "$expected" ]] || {
  echo 'package file inventory differs from the reviewed allowlist' >&2
  diff -u <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") >&2 || true
  exit 1
}

work=$(mktemp -d "${TMPDIR:-/tmp}/plug-prejudice-pkgcheck.XXXXXX")
case $work in "${TMPDIR:-/tmp}"/plug-prejudice-pkgcheck.*) ;; *) exit 1 ;; esac
trap 'case $work in "${TMPDIR:-/tmp}"/plug-prejudice-pkgcheck.*) rm -rf -- "$work" ;; esac' EXIT
for binary in usr/bin/plug-prejudice usr/bin/plug-prejudice-broker; do
  listing=$(bsdtar -tvf "$package" "$binary")
  [[ $listing == -rwxr-xr-x* ]] || { echo "unsafe mode for $binary: $listing" >&2; exit 1; }
  [[ $(awk '{print $3 ":" $4}' <<<"$listing") == root:root ]] || {
    echo "unsafe archive ownership for $binary: $listing" >&2
    exit 1
  }
  extracted="$work/${binary##*/}"
  bsdtar -xOf "$package" "$binary" >"$extracted"
  if ! readelf --file-header "$extracted" >/dev/null 2>&1; then
    echo "$binary is not a readable ELF" >&2
    exit 1
  fi
  if readelf --program-headers "$extracted" | grep -q INTERP \
    || readelf --dynamic "$extracted" 2>/dev/null | grep -q '(NEEDED)'; then
    echo "$binary is not statically linked" >&2
    exit 1
  fi
  chmod 0500 "$extracted"
  "$extracted" --version | grep -Fq "\"reviewerVersion\":\"$version\"" || {
    echo "$binary does not report package version $version" >&2
    exit 1
  }
done

if bsdtar -tf "$package" | grep -Eq '(^|/)\.\.?(/|$)|^/'; then
  echo 'package contains an absolute or traversal path' >&2
  exit 1
fi

echo "Arch package identity, $arch inventory, modes, static ELF properties, and binary versions verified"
