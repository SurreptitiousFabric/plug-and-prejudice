# 0006: Selected-tree path and nested-mount boundary

- Status: implemented; dependency, path-traversal, and independent security approval pending
- Date: 2026-08-27

## Context

The selected plugin is a directory, but Linux permits another filesystem or a
bind mount to appear below that directory. Go documents that `os.Root` does not
prohibit filesystem-boundary or bind-mount traversal. Bubblewrap deliberately
performs recursive bind mounts for `--ro-bind`, so an existing submount is
carried into `/target`. Bubblewrap makes the hierarchy read-only, `nosuid`, and
`nodev`; those flags prevent modification/device use but do not prevent reading
unrelated bytes exposed through the nested mount.

There is also a broker-side parent-path race. The current broker checks the
plugins root with `lstat`, later constructs `root/plugin-id`, and the sandbox
opens that path independently. A concurrent same-user process can replace a
parent component with a symlink between those operations. The final directory
inode is pinned and endpoint symlinks are rejected, but neither proves that the
opened directory remained beneath the root the user selected. The scanner
could therefore receive an unintended readable directory. A lexical path,
`filepath.Abs`, endpoint inode comparison, and a safe plugin ID do not close
this race.

A malicious or compromised already-running user process could therefore mount
unrelated data below an installed plugin before review. Symlink rejection,
inode pinning, and device-ID comparison do not solve this: a bind mount can
refer to the same underlying filesystem and retain the same device ID.

Authoritative references:

- [Go `os.Root` documentation](https://pkg.go.dev/os#Root) explicitly excludes
  filesystem-boundary and bind-mount prevention from its guarantees.
- [Linux `openat2(2)`](https://man7.org/linux/man-pages/man2/openat2.2.html)
  defines beneath-root, no-symlink, no-magic-link, and no-mount-crossing
  resolution for untrusted paths and documents Linux 5.6 as the syscall's
  introduction.
- [`golang.org/x/sys/unix`](https://pkg.go.dev/golang.org/x/sys/unix) exposes
  `Openat2`, `OpenHow`, `Statx`, and the generated Linux constants rather than
  requiring local syscall ABI definitions.
- [Bubblewrap bind setup](https://github.com/containers/bubblewrap/blob/main/bubblewrap.c)
  applies `BIND_RECURSIVE` to directory binds so covered host paths are not
  accidentally uncovered.
- [Bubblewrap bind options](https://github.com/containers/bubblewrap/blob/main/bind-mount.h)
  defines the recursive/read-only/device policy used by that setup.

## Options considered

### Accept nested mounts as target content

Rejected. The user selected a plugin, not arbitrary data mounted below its path.
This would contradict the scanner's privacy boundary even though the mount is
read-only.

### Compare filesystem device IDs

Rejected as incomplete. It detects many filesystem crossings but not same-
filesystem bind mounts and would invite a stronger claim than it can support.

### Parse `/proc/self/mountinfo` in the broker

Rejected. It adds a path-string parser to the trusted unsandboxed broker, is
difficult to bind correctly to the already-open target descriptor, and leaves a
check/use race before Bubblewrap constructs its recursive bind.

### Resolve a canonical string and check its prefix

Rejected. Canonicalization can describe one instant but does not bind later
opens to the same parent hierarchy. Prefix checks are also error-prone around
path-component boundaries and do not constrain a descriptor already opened
through a replaced parent.

### Hand-code Linux `statx` syscall structures

Rejected. Reproducing architecture-specific syscall ABI definitions in security
code is unnecessary when the maintained Go system-call package already exposes
the operation.

### Descriptor-relative selection plus opened-descriptor mount IDs

Recommended. Add the official, pure-Go `golang.org/x/sys/unix` package as a
direct pinned dependency and use one descriptor chain for both boundaries:

1. after entering the resource scope, open and verify the trusted plugins root
   once;
2. select the direct child ID relative to that descriptor with Linux `openat2`
   using `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
   RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`, so selection rejects escapes,
   every symlink/magic-link component, and mount or bind-mount crossings;
3. pass that already-open target descriptor to the sandbox runner instead of
   converting it back to a host path and reopening it;
4. obtain the target mount ID with `unix.Statx` using
   `AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW` and `STATX_MNT_ID`; and
5. before reading each regular file or descending into each directory, obtain
   the mount ID from its already-open descriptor and require equality with the
   target root mount ID.

The file is opened read-only as a directory without creation or mutation flags.
There is no path-based or older-kernel fallback: `ENOSYS`, unsupported resolve
flags, or inability to establish all four resolution properties fails closed
with an actionable broker error. Linux 5.6 is therefore the minimum kernel API
for this selection boundary; supported Omarchy release kernels must be checked
explicitly rather than inferred from the current development host (Linux 7.1.6
on ARM64 at the time of this decision review).

An entry on another mount is inventoried as metadata only, receives
`SkipReason: "nested-mount"`, and adds an explicit `nested-mount` limitation.
The scanner does not open content below that boundary. Failure to obtain a mount
ID fails closed for content inspection rather than degrading to device-ID-only
checks.

## Required verification

Implementation requires:

1. dependency provenance, license, checksum, vulnerability, and binary-size
   review;
2. focused wrapper tests on native ARM64 and AMD64;
3. a real user-namespace mount fixture proving a same-filesystem bind mount is
   not read, with automatic skip where the kernel forbids unprivileged mounts;
4. ordinary directory/file acceptance and cross-mount rejection tests;
5. broker tests proving parent-directory and selected-child symlink swaps cannot
   redirect selection outside the opened plugins root;
6. race tests covering replacement between enumeration, descriptor-relative
   open, and mount-ID verification;
7. Bubblewrap integration proving the exact broker-opened target descriptor is
   mounted and the nested-mount limitation survives report validation; and
8. threat-model and sandbox-policy review by a human before merge.

## Residual risk

Mount IDs bind traversal to one mounted tree during each descriptor check, but
the host can still modify ordinary files in that tree while a read-only sandbox
view exists. Existing inode/link-count/size/mtime/ctime stability checks detect
observable changes around each read; they cannot create an atomic filesystem
snapshot. Reports bind the exact retained bytes and explicit omissions, not an
immutable future state of the plugin.
