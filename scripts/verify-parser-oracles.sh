#!/usr/bin/env bash
set -euo pipefail

# This opt-in dependency-review gate parses only the trusted synthetic bytes
# created below. It never reads an installed plugin or hostile fixture.
for command in python node go mktemp; do
  command -v "$command" >/dev/null 2>&1 || { echo "missing parser oracle: $command" >&2; exit 1; }
done
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/plug-prejudice-oracles.XXXXXX")
cleanup() { case $work in "${TMPDIR:-/tmp}"/plug-prejudice-oracles.*) rm -rf -- "$work" ;; esac; }
trap cleanup EXIT

printf '%s\n' '# fake.call()' "text = 'also.fake()'" "subprocess.run(['whoami'])" >"$work/sample.py"
printf '%s\n' '// fake()' "const text = 'also.fake()';" "child_process.execFile('whoami');" >"$work/sample.js"

python_calls=$(python -c 'import ast,sys; tree=ast.parse(sys.stdin.read()); print(sum(isinstance(n, ast.Call) for n in ast.walk(tree)))' <"$work/sample.py")
test "$python_calls" = 1
node --check "$work/sample.js" >/dev/null

cd -- "$root"
GOFLAGS='-tags=grammar_subset,grammar_subset_python,grammar_subset_javascript' \
  go test ./internal/analyze -run 'Test(Python|JavaScript)SyntaxTreeRecordsCallsButNotCommentOrStringLookalikes$' -count=1
echo 'Python AST and Node syntax oracles agree with the trusted call/lookalike samples'
