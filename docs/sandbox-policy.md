# Deterministic scanner sandbox policy

Status: implemented foundation; resource-scope changes pending human review.

## Boundary

The trusted broker enters and verifies resource containment before either
listing plugin-controlled directory names or resolving a selected plugin. List
mode reads directory entries in batches and rejects the entire operation after
1,024 entries or on any unacceptable entry; it never reads plugin file content.

The broker opens the plugin root and selected directory with Linux `openat2`,
rejecting symlinks, magic links, filesystem crossings, and resolution outside
the pinned root. It gives the exact selected-directory descriptor to
Bubblewrap. Target-controlled text never enters a Bubblewrap option.

Before target resolution, the broker re-enters its pinned running inode in a
randomized transient systemd user scope. It verifies its own cgroup-v2 files and
fails closed unless they prove limits of 256 MiB memory, zero swap, 64 tasks,
and 100% aggregate CPU or stricter. It also disables core dumps and restricts
open file descriptors to at most 256. See
[decision 0003](decisions/0003-systemd-resource-scope.md).

The production broker accepts only a root-owned, non-group/world-writable
scanner inode opened without symlink traversal. It also verifies that this exact
pinned descriptor is an executable ELF with no program interpreter or imported
shared libraries. Release builds therefore use `CGO_ENABLED=0`. Tests may opt
into an explicitly named development mode for a user-owned temporary scanner;
the broker has no flag or production path that enables that weaker mode.

The sandbox is built from an empty mount namespace. It contains only:

- the pinned static scanner at `/app/plug-prejudice`, read-only;
- the pinned selected plugin at `/target`, read-only; and
- a private ephemeral `/tmp`.

The scanner emits its bounded JSON report through a pipe. It has no host-backed
writable output directory.

## Namespace and process policy

The broker requires Bubblewrap and fails closed if it is unavailable. The
current arguments establish:

- fixed root-owned, non-symlink, non-group/world-writable ELF executables at
  `/usr/bin/systemd-run`, `/usr/bin/systemctl`, and `/usr/bin/bwrap`; each is opened with Linux
  `openat2` symlink/magic-link restrictions and executed through its pinned
  `/proc/self/fd/N` inode, so pathname replacement after validation cannot
  substitute a boundary tool; inherited `PATH` is never used;

- new user, mount, PID, IPC, network, UTS, and cgroup namespaces through
  `--unshare-all`;
- an explicit user namespace before disabling further user namespaces;
- `--disable-userns` plus `--assert-userns-disabled`;
- an empty capability set;
- a new session and death with the broker parent; and
- no `/proc`, `/sys`, host `/dev`, home, runtime directory, or session socket
  mounts.

The environment is cleared and rebuilt with only fixed values:

```text
HOME=/nonexistent
PATH=/app
PWD=/target
TMPDIR=/tmp
```

The scoped broker verifies the actual `RuntimeMaxUSec` reported for its exact
randomized unit in addition to reading its cgroup memory, swap, task, and CPU
files. The scope has a verified maximum 35-second lifetime and Bubblewrap
retains an independent 30-second wall-clock timeout. Subprocess waits and pipe
closure have a two-second delay bound. After the scoped broker exits, the outer
broker asks the trusted systemd manager to SIGKILL the exact whole scope, with a
three-second teardown deadline; an already inactive/collected unit is accepted
only as an empty scope. The broker imposes a 16 MiB report limit and a
64 KiB diagnostic limit. Scanner-level limits currently include 10,000 entries,
32 directory levels, 2 MiB per source file, 32 MiB total retained source, 64 MiB
per ELF file, and 128 MiB total ELF input. Source and binary budgets are
independent. Enforced limits are included in scan metadata and must match the
broker's compiled policy.

## Tested guarantees

The Linux integration test builds a trusted static probe and executes it through
the real broker policy. It positively proves target reads and private temporary
writes work, and negatively tests:

- reading host `/etc`;
- reading host home paths;
- writing the target;
- outbound TCP connectivity;
- visibility of host process information; and
- leakage of non-policy environment variables.

The scanner uses descriptor-rooted traversal. For each inspected regular file
and descended directory it compares device/inode, type, mode, size, link count,
mtime, and ctime before and after the observation. A detected rename,
replacement, or modification aborts the scan; it is never returned as ordinary
evidence. This detects concurrent mutation but is not an atomic filesystem
snapshot. A change-and-revert wholly between two metadata observations is a
documented residual race; immutable filesystem snapshots are not required from
arbitrary installed-plugin storage.

The test is run both normally and with Go's race detector. Additional tests
verify the live systemd scope from inside its cgroup, reject missing, unlimited,
or weaker cgroup/runtime controls, trigger real memory and task exhaustion,
terminate a surviving descendant at scope teardown, bound a descendant holding
output descriptors, reject simultaneous stdout/stderr exhaustion, deny cgroup
migration and a nested user namespace, and prove host session sockets are absent.

## Non-claims

Bubblewrap is a policy construction tool, not a security guarantee by itself.
These tests demonstrate behavior on supported Linux environments; they do not
prove the absence of kernel, Bubblewrap, Go runtime, or scanner vulnerabilities.
Root, kernel, package-manager, or systemd-manager compromise is outside the
attacker model. Production scanner immutability relies on ordinary root-owned
installation permissions; development-mode scanner execution makes no such
production claim.
