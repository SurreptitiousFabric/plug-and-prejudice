# ADR 0004: Arch package trust boundary

- Status: implemented in development tree; owner approval, native package evidence, and human security review pending
- Date: 2026-08-27

## Context

Omarchy installs a third-party plugin by cloning its Git repository into the
user-owned plugin directory. The installer validates the manifest but
deliberately runs no plugin hook, build, package-manager, or privileged command.
That is a documented Omarchy security property and must remain true.

The panel currently resolves `bin/plug-prejudice-broker` relative to its cloned
source directory. A normal clone does not contain a built Go binary, and a
binary stored there would be writable by the user and by any already-enabled
plugin running with the same authority. That does not provide the trusted
executable boundary assumed by the broker and sandbox design.

## Options

### 1. Separate Arch package for the trusted executables (recommended)

Install `plug-prejudice` and `plug-prejudice-broker` as root-owned regular files
under `/usr/bin`. Keep the Git-cloned Omarchy plugin as the thin QML integration
and have it invoke the fixed `/usr/bin/plug-prejudice-broker` path.

The package would depend on the system `bubblewrap` and `systemd` packages,
build from a pinned release source with integrity verification, run tests during
`check()`, and install no files into a user's home directory. Plugin installation
and package installation remain explicit separate operations.

Advantages:

- aligns executable ownership with the existing trusted-tool checks;
- follows Arch filesystem conventions;
- preserves Omarchy's hook-free Git installer;
- lets Pacman record, verify, upgrade, and remove executable files; and
- keeps the standalone CLI independent of Omarchy.

Costs:

- installation has two explicit steps;
- UI/broker protocol compatibility must fail clearly when versions differ; and
- an AUR or other package publication process becomes part of release work.

### 2. Commit or download binaries into the plugin checkout

This makes `omarchy plugin add` appear self-contained, but the executable is
user-writable, architecture-specific, difficult to review in update diffs, and
outside Pacman's ownership and verification. Downloading it on first use would
also add network and code-installation behavior to the trusted UI boundary.

Rejected.

### 3. Build or install from QML on first use

This would require the thin wrapper to run a compiler or package manager and
possibly request privilege. It violates the Omarchy installer's no-hook model,
greatly expands the wrapper's responsibility, and makes review itself perform
security-sensitive installation work.

Rejected.

### 4. Install the complete plugin under `/usr/share/omarchy`

Third-party packages must not modify Omarchy-owned files. Arch packages also
must not install into a user's home directory, while Omarchy discovers
third-party plugins there. Installing a parallel packaged copy would create
unclear ownership and update behavior.

Rejected.

## Recommended build profile

Both Go commands should be built on the target architecture with:

- `-trimpath` and `-mod=readonly`;
- `-buildmode=pie`;
- external `-static-pie` linking;
- `netgo,osusergo` build tags; and
- the release version injected through an audited linker variable once that
  version interface exists.

On the current ARM64 Arch system, this profile produced an AArch64 ET_DYN static
PIE with no `PT_INTERP`, no `DT_NEEDED` entries, no linker warnings, and
byte-identical output across two separate build directories. In contrast,
`CGO_ENABLED=0 -buildmode=pie` produced a `PT_INTERP` entry and failed the
scanner's verified-static invariant. Static PIE uses CGO only to select the
external linker; the `netgo,osusergo` tags prevent libc resolver/user lookup
paths from entering normal Go behavior.

The package must verify these ELF properties during `check()` rather than rely
on build flags alone. It must build and test natively on both `aarch64` and
`x86_64`; cross-compilation is not release evidence.

## Compatibility and failure behavior

Before changing the panel path, the broker needs a small machine-readable
protocol/version handshake. The panel must show an actionable installation or
version-mismatch error and must never fall back to a sibling executable, `PATH`,
network download, build step, or shell command.

The broker must validate that the scanner is a root-owned, non-symlink regular
executable in addition to its existing inode pinning and static-ELF checks. The
standalone CLI remains directly usable without the panel.

## Approval gate

Approval of this ADR authorizes implementation of the fixed executable path,
version handshake, Arch packaging files, package-build tests, and installation
documentation. It does not authorize publishing an AUR package or release,
installing the package on the machine, enabling the plugin, or merging the
security-relevant changes without human review.
