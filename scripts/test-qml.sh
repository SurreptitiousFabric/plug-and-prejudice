#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

qml_lint=${QMLLINT:-/usr/lib/qt6/bin/qmllint}
omarchy_qml_root=${OMARCHY_QML_ROOT:-/usr/share/omarchy/shell}

for command in quickshell timeout; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "test-qml: missing command: $command" >&2
    exit 1
  }
done
[[ -x $qml_lint ]] || { echo "test-qml: qmllint is unavailable" >&2; exit 1; }
for module in Commons Ui; do
  [[ -d $omarchy_qml_root/$module ]] || {
    echo "test-qml: missing Omarchy QML module: $module" >&2
    exit 1
  }
done

work=$(mktemp -d "${TMPDIR:-/tmp}/plug-prejudice-qml.XXXXXX")
case $work in
  "${TMPDIR:-/tmp}"/plug-prejudice-qml.*) ;;
  *) echo "test-qml: unsafe temporary path" >&2; exit 1 ;;
esac
cleanup() {
  case $work in
    "${TMPDIR:-/tmp}"/plug-prejudice-qml.*) rm -rf -- "$work" ;;
  esac
}
trap cleanup EXIT

mkdir -p "$work/imports/qs"
ln -s "$omarchy_qml_root/Commons" "$work/imports/qs/Commons"
ln -s "$omarchy_qml_root/Ui" "$work/imports/qs/Ui"

for source in Panel.qml tests/PanelVisualHarness.qml; do
  set +e
  lint_output=$($qml_lint -I "$work/imports" -I . -I /usr/lib/qt6/qml "$source" 2>&1)
  lint_status=$?
  set -e
  if (( lint_status != 0 )) || grep -E -q '\[(syntax|unqualified)\]' <<<"$lint_output"; then
    printf '%s\n' "$lint_output" >&2
    echo "test-qml: QML type validation failed: $source" >&2
    exit 1
  fi
done

cp Panel.qml "$work/Panel.qml"
cp tests/PanelLoadTest.qml "$work/shell.qml"
ln -s "$omarchy_qml_root/Commons" "$work/Commons"
ln -s "$omarchy_qml_root/Ui" "$work/Ui"

set +e
runtime_output=$(timeout 8 quickshell --no-duplicate --no-color --path "$work/shell.qml" 2>&1)
runtime_status=$?
set -e
printf '%s\n' "$runtime_output"
if (( runtime_status != 0 )) || ! grep -Fq PLUG_PREJUDICE_PANEL_PASS <<<"$runtime_output" \
    || grep -E -q 'PLUG_PREJUDICE_PANEL_FAIL|TypeError|ReferenceError|is not a type|Cannot assign' <<<"$runtime_output"; then
  echo "test-qml: Quickshell component-load test failed" >&2
  exit 1
fi

echo "QML type, hostile-text, and component-load checks passed"
