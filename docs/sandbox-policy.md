# Deterministic scanner sandbox policy

Status: implemented foundation; resource-scope changes pending human review.

## Boundary

The broker enters and verifies the resource scope before enumerating any
plugin-controlled directory name. List mode reads fixed-size batches, retains a
bounded set, and rejects overflow or any unacceptable entry without reading
plugin file content.

The broker opens the trusted configured plugin root without symlink or
magic-link traversal while allowing ordinary host mount crossings needed to
reach trusted configuration. It selects the direct child beneath that pinned
descriptor with no-symlink/no-magic-link/no-cross-mount resolution and passes
the same opened target to Bubblewrap. PR #22 establishes this selection
boundary. The later selected-tree implementation additionally establishes the
target mount ID and applies descriptor-relative no-cross-mount resolution to
each child open; nested mount entries remain metadata-only with an explicit
limitation.
Regular files with more than one hard link are inventoried but not opened,
because another name for the same inode may be outside the selected plugin.
This omission is an explicit limitation and makes the report incomplete.
Target-controlled text never enters a Bubblewrap option.

Before target resolution, the broker re-enters its pinned running inode in a
randomized transient systemd user scope. It verifies its own cgroup-v2 files and
fails closed unless they prove limits of 256 MiB memory, zero swap, 64 tasks,
and 100% aggregate CPU or stricter. It also disables core dumps and restricts
open file descriptors to at most 256. See
[decision 0003](decisions/0003-systemd-resource-scope.md).

The production broker requires the pinned scanner to be a root-owned,
non-group/world-writable executable ELF with no
program interpreter or imported shared libraries. Release builds therefore use
`CGO_ENABLED=0`. This preserves the deliberately empty runtime filesystem and
turns an incorrectly linked package into a clear fail-closed error. Tests may
explicitly allow a user-owned development scanner; no broker flag enables that
weaker mode.

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

When optional Omarchy audit evidence is explicitly supplied, the broker pins a
single non-symlink regular-file descriptor and adds one read-only bind at
`/audit/omarchy.json`. No containing directory or upstream `pluginDir` path is
mounted. The scanner receives the pinned format identifier as a fixed argument;
target content cannot select it. Omitting the evidence flags leaves this mount
absent.

The outer broker also does not pass its user-session environment to
`systemd-run` or `systemctl`. It validates the euid-owned, non-group/world
accessible `/run/user/<euid>` directory and supplies only that
`XDG_RUNTIME_DIR`, fixed C locale, and fixed systemd no-pager/no-color/no-URL
settings. In particular, loader, D-Bus-address override, `SYSTEMD_*` override,
`XDG_CONFIG_*`, pager, and Go-runtime variables are not inherited.

The scoped broker verifies the actual `RuntimeMaxUSec` reported for its exact
randomized unit in addition to reading its cgroup memory, swap, task, and CPU
files. The scope has a verified maximum 35-second lifetime and Bubblewrap
retains an independent 30-second wall-clock timeout. Subprocess waits and pipe
closure have a two-second delay bound. After the scoped broker exits, the outer
broker asks the trusted systemd manager to SIGKILL the exact whole scope, then
polls the validated cgroup until `cgroup.events` reports `populated 0` or the
cgroup has been collected, all within a three-second teardown deadline. A
collected unit or an inactive/failed unit with no control-group path is accepted
as already empty; acceptance of `systemctl kill --no-block` is not sufficient.
The broker imposes a 16 MiB report limit and a
64 KiB diagnostic limit. Crossing either stream bound cancels the child as soon
as that copy observes overflow; cancellation does not wait for the other stream
to close. Before a failed scanner diagnostic reaches broker stderr, C0/C1
terminal controls and the complete Unicode `Bidi_Control` set are replaced
while newline and tab remain readable; malformed UTF-8 is replaced
byte-for-byte so sanitized output cannot exceed the input bound. All
broker-generated errors and standalone-scanner diagnostics then cross the same
plain-text normalizer with a 4 KiB ceiling before stderr reaches either a
terminal or the Omarchy process collector. Raw flag-parser errors are also
suppressed in favor of this path. The broker bound covers strict-decoder errors
that can quote hostile JSON field names; UI-side truncation is not treated as a
process-memory control. Scanner-level limits currently include 10,000 entries,
32 directory levels, 2 MiB per source file, 32 MiB total retained source, 64 MiB
per ELF file, and 128 MiB total ELF input. Source and binary budgets are
independent. Directory enumeration itself is incremental and retains at most
the remaining file-count budget plus one overflow sentinel. If a directory
exceeds that remaining budget, the scanner omits that directory as a unit and
adds a `max-files` limitation instead of materializing the full listing or
choosing a filesystem-order-dependent subset. Enforced limits are included in
scan metadata and must match the broker's compiled policy.

The end-to-end broker-operation policy deadline is 42 seconds: 35 seconds for
the systemd-scoped command, up to 2 seconds for its process/pipe reaping, up to
3 seconds for teardown actions and cgroup-empty observation, and up to 2
seconds for a final trusted `systemctl` process/pipe reap. The scanner's
30-second limit plus its 2-second reaping allowance stays inside the 35-second
scope lifetime. Caller cancellation triggers detached cleanup but cannot extend
the original absolute operation deadline.

Systemd 261 is the documented compatibility baseline. With fixed C locale, the
configured `RuntimeMaxSec=35s` is observed as `35s\n` from
`systemctl show --property=RuntimeMaxUSec --value --no-pager`. The bounded
parser accepts only non-negative decimal `us`, `ms`, or `s` forms emitted by the
supported interface and rejects unfamiliar syntax as an availability failure.

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

The scanner uses descriptor-rooted traversal and retains a bounded observation
manifest. After all initial reads it performs a second descriptor-rooted pass
over the complete observed tree, comparing directory membership, device/inode,
type, mode, size, link count, mtime, ctime, and symlink targets. A mismatch
aborts the complete scan and returns no ordinary evidence. This establishes a
stable observed tree across two bounded passes, not an atomic filesystem
snapshot. A change-and-revert wholly between observations remains a documented
residual race.
The test is run both normally and with Go's race detector. Additional tests
verify the live systemd scope from inside its cgroup, reject missing, unlimited,
or weaker cgroup/runtime controls, trigger real memory and task exhaustion,
terminate a surviving descendant at scope teardown, bound a descendant holding
output descriptors, reject simultaneous and asymmetric stdout/stderr
exhaustion (including a retained opposite pipe), exclude hostile inherited
environment overrides from live systemd operations, deny cgroup
migration and a nested user namespace, and prove host session sockets are
absent. A separate diagnostic-overflow probe writes beyond the stderr bound and
then sleeps; the test proves the broker cancels promptly rather than waiting
for stdout or the wall deadline.

## Non-claims

Bubblewrap is a policy construction tool, not a security guarantee by itself.
These tests demonstrate behavior on supported Linux environments; they do not
prove the absence of kernel, Bubblewrap, Go runtime, or scanner vulnerabilities.
Root, kernel, package-manager, or systemd-manager compromise is outside the
attacker model. Production scanner immutability relies on ordinary root-owned
installation permissions; development-mode scanner execution makes no such
production claim.
The supported higher-assurance path is the independently root-installed CLI
launched from the normal host session. Starting it inside an attacker-created
user or mount namespace with forged views of `/usr`, `/run`, procfs, or
cgroupfs is outside the containment claim; the broker does not authenticate an
arbitrary caller's namespaces. Hostile static plugin files remain in scope.
