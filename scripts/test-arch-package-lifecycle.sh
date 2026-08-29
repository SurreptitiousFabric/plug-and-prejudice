#!/usr/bin/env bash
set -euo pipefail

if (( $# != 4 )); then
  echo 'usage: test-arch-package-lifecycle.sh OLD_VERSION OLD_PACKAGE NEW_VERSION NEW_PACKAGE' >&2
  exit 2
fi
old_version=$1
old_package=$2
new_version=$3
new_package=$4
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
config="$root/packaging/arch/pacman-isolated.conf"

for command in pacman sha256sum stat unshare; do
  command -v "$command" >/dev/null 2>&1 || { echo "missing command: $command" >&2; exit 1; }
done
if (( EUID == 0 )); then
  echo 'run as an unprivileged user; this harness creates its own user namespace' >&2
  exit 2
fi
if ! unshare --user --map-root-user true 2>/dev/null; then
  echo 'unprivileged user namespaces are unavailable' >&2
  exit 1
fi

"$root/scripts/verify-built-arch-package.sh" "$old_version" "$old_package"
"$root/scripts/verify-built-arch-package.sh" "$new_version" "$new_package"
old_package=$(realpath --canonicalize-existing -- "$old_package")
new_package=$(realpath --canonicalize-existing -- "$new_package")

test_root=$(mktemp -d "${TMPDIR:-/tmp}/plug-prejudice-pacman-root.XXXXXX")
case $test_root in "${TMPDIR:-/tmp}"/plug-prejudice-pacman-root.*) ;; *) exit 1 ;; esac
trap 'case $test_root in "${TMPDIR:-/tmp}"/plug-prejudice-pacman-root.*) rm -rf -- "$test_root" ;; esac' EXIT
mkdir -p "$test_root/var/lib/pacman/local" "$test_root/var/cache/pacman/pkg" \
  "$test_root/var/log" "$test_root/usr/bin" "$test_root/hooks"

pacman_args=(
  --config "$config"
  --root "$test_root"
  --dbpath "$test_root/var/lib/pacman"
  --cachedir "$test_root/var/cache/pacman/pkg"
  --logfile "$test_root/var/log/pacman.log"
  --hookdir "$test_root/hooks"
)

install_package() {
  unshare --user --map-root-user pacman "${pacman_args[@]}" \
    --noscriptlet --noconfirm --assume-installed bubblewrap=1 --assume-installed systemd=1 -U "$1"
}

verify_installed() {
  local expected=$1
  [[ $(unshare --user --map-root-user pacman "${pacman_args[@]}" -Q plug-and-prejudice) \
      == "plug-and-prejudice ${expected}-1" ]]
  for binary in plug-prejudice plug-prejudice-broker; do
    unshare --user --map-root-user sh -c \
      'test "$(stat -c "%U:%G:%a" "$1")" = root:root:755' sh "$test_root/usr/bin/$binary"
    unshare --user --map-root-user pacman "${pacman_args[@]}" -Ql plug-and-prejudice \
      | grep -Fxq "plug-and-prejudice $test_root/usr/bin/$binary"
    "$test_root/usr/bin/$binary" --version \
      | grep -Fq "\"reviewerVersion\":\"$expected\""
  done
}

install_package "$old_package"
verify_installed "$old_version"
old_scanner="$test_root/usr/bin/plug-prejudice"
old_inode=$(stat -c '%d:%i' "$old_scanner")
old_path_hash=$(sha256sum "$old_scanner" | awk '{print $1}')
exec {old_scanner_fd}<"$old_scanner"
old_fd_hash=$(sha256sum "/proc/self/fd/$old_scanner_fd" | awk '{print $1}')
[[ $old_fd_hash == "$old_path_hash" ]]
install_package "$new_package"
verify_installed "$new_version"
new_inode=$(stat -c '%d:%i' "$old_scanner")
new_path_hash=$(sha256sum "$old_scanner" | awk '{print $1}')
preserved_fd_hash=$(sha256sum "/proc/self/fd/$old_scanner_fd" | awk '{print $1}')
[[ $new_inode != "$old_inode" ]] || {
  echo 'package upgrade modified the installed scanner inode in place' >&2
  exit 1
}
[[ $new_path_hash != "$old_path_hash" ]] || {
  echo 'versioned package upgrade did not replace scanner bytes' >&2
  exit 1
}
[[ $preserved_fd_hash == "$old_fd_hash" ]] || {
  echo 'package upgrade mutated the already-open production scanner inode' >&2
  exit 1
}
exec {old_scanner_fd}<&-
unshare --user --map-root-user pacman "${pacman_args[@]}" --noconfirm -R plug-and-prejudice

for binary in plug-prejudice plug-prejudice-broker; do
  [[ ! -e $test_root/usr/bin/$binary && ! -L $test_root/usr/bin/$binary ]] || {
    echo "removal left installed path: /usr/bin/$binary" >&2
    exit 1
  }
done
if unshare --user --map-root-user pacman "${pacman_args[@]}" -Q plug-and-prejudice >/dev/null 2>&1; then
  echo 'isolated package database still reports plug-and-prejudice after removal' >&2
  exit 1
fi

echo 'Isolated Pacman install, ownership, upgrade, version handshake, and removal checks passed'
