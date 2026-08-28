# Dependency and supply-chain audit

Status: development-tree inventory; regenerate and review for every release
candidate.

The scanner processes hostile input, so every parser and runtime component is
part of its attack surface. A small dependency graph reduces, but does not
eliminate, supply-chain and parser risk.

## Production Go dependencies

The two product binaries have three pinned non-standard-library module dependencies:

| Module | Version | Purpose | License | Integrity source |
|---|---:|---|---|---|
| `github.com/odvcencio/gotreesitter` | `v0.51.0` | Pure-Go, non-executing Python and JavaScript syntax trees with only those two grammar blobs embedded | MIT | Exact module and `go.mod` hashes in `go.sum`; upstream grammar lock records provenance |
| `golang.org/x/sys` | `v0.47.0` | Official Linux `openat2`, `statx`, and descriptor-relative filesystem APIs | BSD-3-Clause | Exact module and `go.mod` hashes in `go.sum` |
| `mvdan.cc/sh/v3` | `v3.13.1` | Parse shell source into an AST without evaluating it | BSD-3-Clause | Exact module and `go.mod` hashes in `go.sum` |

The scanner imports `mvdan.cc/sh/v3/syntax` and
`mvdan.cc/sh/v3/fileutil`. It does not import the package's shell interpreter.
The broker imports `x/sys/unix`; the scanner imports it for mount-boundary
traversal and imports the pure-Go parser runtime. Production builds require the
`grammar_subset_python` and `grammar_subset_javascript` tags so the remaining
grammar registry is not embedded. The required binary
distribution notice is retained in [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).

This inventory was derived with:

```bash
go list -tags 'grammar_subset grammar_subset_python grammar_subset_javascript' -deps -f '{{with .Module}}{{if and (not .Main) .Path}}{{.Path}} {{.Version}}{{end}}{{end}}' \
  ./cmd/plug-prejudice ./cmd/plug-prejudice-broker | sort -u
```

Only the three reviewed modules above appear. Static linkage and the absence of a
dynamic interpreter or shared-library requirement are independently checked by
`scripts/verify-reproducible-build.sh`.
`scripts/verify-production-dependencies.sh` makes the expected set and required
notice text a failing development gate; an intentional dependency update must
update the verifier, audit, license review, and notice together.

## Graph-only test dependencies

`go.sum` also records these modules because the selected shell parser's own
package tests depend on them:

- `github.com/go-quicktest/qt v1.101.0`
- `github.com/google/go-cmp v0.7.0`
- `github.com/kr/pretty v0.3.1`
- `github.com/kr/text v0.2.0`
- `github.com/rogpeppe/go-internal v1.14.1`

`go mod why -m MODULE` traces each through
`mvdan.cc/sh/v3/syntax.test`; none is linked into either product command. Other
modules shown by `go list -m all` but absent from `go.sum` are requirements in
an upstream module graph that this build did not download or compile. They are
not silently described as shipped dependencies.

## Host tools and platform dependencies

The installed product deliberately relies on separately packaged, root-owned
host components:

- the Go toolchain builds the static binaries but is not required at runtime;
- Bubblewrap establishes the filesystem, process, and network namespace;
- the systemd user manager establishes the transient resource scope;
- Omarchy Shell hosts the thin QML integration.

These are not vendored into this repository and are not covered by the Go
module hashes. Their accepted paths, ownership, permissions, versions, package
ownership, and compatibility must be verified by the final Arch package and
release process after ADR 0004 is approved. Bubblewrap and systemd are security
boundaries, not incidental conveniences.

## Release-only SBOM tool

The publish job uses `cyclonedx-gomod v1.10.0` only to describe the reviewed Go
module; it is not linked into or installed with either product binary. The job
downloads the official Linux AMD64 release archive and requires SHA-256
`5cce8ae99a5181be6a610ea5ed9ca9d596937cc04dc1a8f6f6b5e462d8c9900e`
for AMD64 or
`b2bebbe569c39b6bd62b7a142269a8870795020ef608483c942e4b7f51f4de6b`
for ARM64 before extraction. The reviewed identities are centralized in
`packaging/release-tools.env` and checked by
`scripts/verify-release-tool-pin.sh`. `generate-release-metadata.sh` requires
the already-verified executable on `PATH` and performs no tool download or
source build itself. It creates one module SBOM plus a separate SBOM from the
embedded Go build information of each ARM64/x86-64 scanner and broker binary;
the tool documents that binary inspection does not execute those binaries. The
publish job supplies the repository-pinned Go toolchain because binary mode
uses `go version -m` as a metadata reader; it does not use Go to compile the
SBOM generator.

This pin authenticates bytes, not trustworthiness. A release reviewer must
reconcile the digest with the upstream signed/checksummed release, inspect tool
release provenance and vulnerabilities, and review the generated SBOM.

## Release review procedure

For every release candidate:

1. review any `go.mod` or `go.sum` diff and explain each new module;
2. run `scripts/verify-production-dependencies.sh`, then repeat `go mod verify`
   from a clean module cache or controlled builder;
3. regenerate the production linkage query above for both architectures;
4. run the pinned `govulncheck` gate and retain its result with release
   evidence;
5. verify all shipped third-party licenses and notices;
6. generate and inspect the final package SBOM after package contents are
   defined; and
7. inspect the final static binaries and package file list rather than treating
   this development inventory as release proof.

This document is an auditable snapshot, not an assertion that dependencies are
safe or that future versions have the same graph.

`scripts/verify-vulnerabilities.sh` pins `govulncheck v1.7.0` and invokes it
through `go run` with read-only project-module behavior. Go authenticates the
download according to the builder's configured module proxy and checksum
database policy; the tool is not vendored into this repository. A release must
record that policy and the actual command output. “No vulnerabilities found”
means only that this tool version and its current database found no known
reachable Go vulnerability; it does not establish that the reviewer is safe
and does not assess Bubblewrap, systemd, Omarchy, or the host kernel.
