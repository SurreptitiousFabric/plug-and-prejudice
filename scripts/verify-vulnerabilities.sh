#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$repo_root"

# Keep this version synchronized with the release-stack dependency audit. The
# explicit module version prevents an ambient or mutable PATH tool from deciding
# the result. Go verifies downloaded module content through its configured proxy
# and checksum database policy.
readonly govulncheck_version='v1.7.0'
GOFLAGS='-mod=readonly' go run "golang.org/x/vuln/cmd/govulncheck@${govulncheck_version}" ./...
