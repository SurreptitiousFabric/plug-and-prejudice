#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
tool_file="$root/packaging/release-tools.env"
workflow="$root/.github/workflows/release.yml"
generator="$root/scripts/generate-release-metadata.sh"

# shellcheck disable=SC1090 -- this is the exact reviewed repository file.
source "$tool_file"
[[ $CYCLONEDX_GOMOD_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
[[ $CYCLONEDX_GOMOD_LINUX_AMD64_SHA256 =~ ^[0-9a-f]{64}$ ]]
[[ $CYCLONEDX_GOMOD_LINUX_ARM64_SHA256 =~ ^[0-9a-f]{64}$ ]]
test "$(grep -Ec '^[A-Z0-9_]+=' "$tool_file")" = 3
grep -Fq 'scripts/install-release-sbom-tool.sh .release-tools' "$workflow"
grep -Fq "curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error" "$root/scripts/install-release-sbom-tool.sh"
grep -Fq 'sha256sum --check --strict' "$root/scripts/install-release-sbom-tool.sh"
grep -Fq 'tar -xzf "$archive" -C "$destination" cyclonedx-gomod' "$root/scripts/install-release-sbom-tool.sh"
grep -Fq 'for command in cyclonedx-gomod file go readelf sha256sum' "$generator"
if grep -Fq 'go run github.com/CycloneDX/cyclonedx-gomod' "$generator"; then
  echo 'verify-release-tool-pin: generator resolves CycloneDX source at release time' >&2
  exit 1
fi

echo "CycloneDX release tool is version- and artifact-digest-pinned"
