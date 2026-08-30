#!/usr/bin/env bash
set -euo pipefail

if (( $# != 3 )); then
  echo "usage: $0 NOTICE_FILE 'MODULE VERSION' LICENSE_FILE" >&2
  exit 2
fi

readonly notice_file=$1
readonly identity=$2
readonly license_file=$3
readonly begin_marker="<!-- BEGIN VERBATIM LICENSE: $identity -->"
readonly end_marker="<!-- END VERBATIM LICENSE: $identity -->"

mapfile -t begin_lines < <(grep -nFx -- "$begin_marker" "$notice_file" | cut -d: -f1)
mapfile -t end_lines < <(grep -nFx -- "$end_marker" "$notice_file" | cut -d: -f1)
if (( ${#begin_lines[@]} != 1 || ${#end_lines[@]} != 1 )); then
  echo "$notice_file must contain exactly one marked licence block for $identity" >&2
  exit 1
fi
if (( end_lines[0] <= begin_lines[0] )); then
  echo "$notice_file has invalid licence-block marker order for $identity" >&2
  exit 1
fi

extracted=$(mktemp)
trap 'rm -f -- "$extracted"' EXIT
sed -n "$((begin_lines[0] + 1)),$((end_lines[0] - 1))p" "$notice_file" >"$extracted"

if ! cmp -s -- "$license_file" "$extracted"; then
  echo "$notice_file does not reproduce $identity licence bytes exactly" >&2
  exit 1
fi
