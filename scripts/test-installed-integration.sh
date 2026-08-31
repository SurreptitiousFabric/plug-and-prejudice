#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

for command in quickshell timeout /usr/bin/plug-prejudice /usr/bin/plug-prejudice-broker; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "test-installed-integration: missing command: $command" >&2
    exit 1
  }
done

omarchy_qml_root=${OMARCHY_QML_ROOT:-/usr/share/omarchy/shell}
work=$(mktemp -d "${TMPDIR:-/tmp}/plug-prejudice-integration.XXXXXX")
case $work in
  "${TMPDIR:-/tmp}"/plug-prejudice-integration.*) ;;
  *) echo "test-installed-integration: unsafe temporary path" >&2; exit 1 ;;
esac
cleanup() {
  case $work in
    "${TMPDIR:-/tmp}"/plug-prejudice-integration.*) rm -rf -- "$work" ;;
  esac
}
trap cleanup EXIT

cp Panel.qml "$work/Panel.qml"
cp tests/PanelIntegrationTest.qml "$work/shell.qml"
ln -s "$omarchy_qml_root/Commons" "$work/Commons"
ln -s "$omarchy_qml_root/Ui" "$work/Ui"

set +e
output=$(PLUG_PREJUDICE_TEST_SOURCE="$work" \
  PLUG_PREJUDICE_TEST_PLUGIN="${PLUG_PREJUDICE_TEST_PLUGIN:-}" \
  timeout 25 quickshell --no-duplicate --no-color --path "$work/shell.qml" 2>&1)
status=$?
set -e
printf '%s\n' "$output"
if (( status != 0 )) || ! grep -Fq PLUG_PREJUDICE_INTEGRATION_PASS <<<"$output" \
    || grep -E -q 'PLUG_PREJUDICE_INTEGRATION_FAIL|TypeError|ReferenceError|is not a type|Cannot assign' <<<"$output"; then
  echo "test-installed-integration: panel/broker/sandbox integration failed" >&2
  exit 1
fi

echo "Installed-plugin panel integration passed"
