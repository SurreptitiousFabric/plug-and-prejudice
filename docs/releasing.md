# Release procedure

This is a maintainer procedure, not an automatic declaration that the product
or a reviewed plugin is safe. Do not create a version tag until every required
human gate in `release-readiness.md` is recorded as approved.

## Candidate preparation

1. Start from a clean commit reviewed at the intended release tag.
2. Run all change gates, including race tests, QML checks, dependency review,
   vulnerability scanning, and package-template verification.
3. Obtain native Arch package and installation evidence on both `aarch64` and
   `x86_64`. Cross-compilation is not a substitute for either native run.
4. Review the final dependency graph, CycloneDX SBOM procedure, workflow action
   pins, permissions, and every file intended for publication.
5. Create and push an annotated signed `vX.Y.Z` tag only after approval.

The tag-only release workflow builds on native GitHub-hosted ARM64 and x86-64
runners. Each build runs tests, produces version-injected static binaries, and
executes both binaries' machine-readable `--version` interface natively before
upload. The publish job refuses a missing architecture, wrong ELF machine, or
dynamic dependency. It then creates a timestamp-free
CycloneDX 1.6 module SBOM, writes a SHA-256 manifest, verifies that manifest,
attests every subject through GitHub's OIDC-backed artifact-attestation service,
and attaches the same files to the tag's GitHub release.

SBOM generation does not compile a tool dynamically with `go run`. The publish
job downloads the exact CycloneDX release artifact named in
`packaging/release-tools.env`, verifies its pinned SHA-256 before extraction,
and places only that executable on the job-local path.
The release contains an aggregate module SBOM and one binary-specific SBOM for
each scanner/broker architecture. All five SBOMs and all four binaries are
covered by the published checksum manifest and artifact attestation.

The workflow does not build an Arch package and is not Pacman ownership
evidence. Those remain separate native release gates.

The supported containment claim applies to the independently installed CLI
launched from the normal host session. Release and installation evidence must
not invoke it from an attacker-created user or mount namespace or imply that
the broker authenticates an arbitrary namespace view. The Omarchy wrapper is a
convenience path inside the desktop process; an already-enabled malicious
same-user plugin may already interfere with that session.

For each native Arch candidate, first run
`scripts/verify-built-arch-package.sh X.Y.Z PACKAGE`, then run
`scripts/test-arch-package-lifecycle.sh OLD_VERSION OLD_PACKAGE NEW_VERSION
NEW_PACKAGE`. The latter creates an unprivileged user namespace and a temporary
Pacman root, with no repositories, hooks, scriptlets, or network sources. It
installs the already-offline-verified local packages, verifies namespace-root
ownership and Pacman file records, upgrades, checks the broker version
handshake, removes the package, confirms both files and database state are
gone, and deletes the temporary root. The upgrade test holds the old scanner
inode open, proves the new path has a different inode and versioned bytes, and
proves the old descriptor's bytes did not change; supported packaging therefore
replaces the root-owned scanner rather than modifying a live inode in place. It
never writes the host package database
or host `/usr/bin`.

`packaging/arch/pacman-isolated.conf` disables signatures solely inside that
offline test root. It is not an installation configuration and must never be
used for a downloaded/public artifact. Final release evidence must additionally
install the signed candidate with the normal system Pacman policy on disposable
native ARM64 and x86-64 machines.

## Consumer verification

Download every desired artifact plus `plug-and-prejudice-X.Y.Z.sha256`, then
verify the complete downloaded set from its directory:

```text
sha256sum --check plug-and-prejudice-X.Y.Z.sha256
```

Verify GitHub's signed provenance for each artifact against this repository:

```text
gh attestation verify ARTIFACT --repo SurreptitiousFabric/plug-and-prejudice
```

Also verify the annotated release tag using the maintainer signing identity.
Checksums detect changed bytes; the attestation binds subjects to the workflow;
the signed tag identifies the maintainer-approved source. None replaces the
other two.
