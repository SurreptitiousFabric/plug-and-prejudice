# Deterministic scanner sandbox policy

Status: implemented foundation; resource-scope changes pending human review.

## Boundary

The trusted broker opens the plugins root once, selects the direct child ID
relative to that descriptor with `openat2` beneath/no-symlink/no-magic-link/
no-cross-mount resolution, and passes the same already-open target descriptor
to Bubblewrap. Target-controlled text never enters a Bubblewrap option. The
scanner establishes the target mount ID and applies the same resolution policy
to each child open; nested mount entries remain metadata-only with an explicit
limitation.
Regular files with more than one hard link are inventoried but not opened,
because another name for the same inode may be outside the selected plugin.
This omission is an explicit limitation and makes the report incomplete.
Regular source and ELF reads require the opened inode, size, modification time,
and change time to remain consistent from the pre-read stat through the
post-read stat; detected races make the report incomplete.

Before target resolution, the broker re-enters its pinned running inode in a
randomized transient systemd user scope. It verifies its own cgroup-v2 files and
fails closed unless they prove limits of 256 MiB memory, zero swap, 64 tasks,
and 100% aggregate CPU or stricter. It also disables core dumps and restricts
open file descriptors to at most 256. See
[decision 0003](decisions/0003-systemd-resource-scope.md).

The broker also verifies that the pinned scanner is an executable ELF with no
program interpreter or imported shared libraries. Release builds therefore use
`CGO_ENABLED=0`. This preserves the deliberately empty runtime filesystem and
turns an incorrectly linked package into a clear fail-closed error.

The sandbox is built from an empty mount namespace. It contains only:

- the pinned static scanner at `/app/plug-prejudice`, read-only;
- the pinned selected plugin at `/target`, read-only; and
- a private ephemeral `/tmp`.

The scanner emits its bounded JSON report through a pipe. It has no host-backed
writable output directory.

## Namespace and process policy

The broker requires Bubblewrap and fails closed if it is unavailable. The
current arguments establish:

- fixed root-owned, non-symlink, non-group/world-writable executables at
  `/usr/bin/systemd-run` and `/usr/bin/bwrap`; inherited `PATH` is never used to
  choose a boundary tool;

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

The parent requests a 35-second systemd-scope lifetime and Bubblewrap retains
an independent 30-second wall-clock timeout. Live lifetime-property verification
remains pending ADR 0003. The broker imposes a 16 MiB report limit and a
64 KiB diagnostic limit. Crossing either stream bound cancels the child as soon
as that reader detects it; cancellation does not wait for the other stream to
close. Before a failed scanner diagnostic reaches broker
stderr, C0/C1 terminal controls and the complete Unicode `Bidi_Control` set are
replaced while newline and tab remain readable; malformed UTF-8
is replaced byte-for-byte so sanitized output cannot exceed the input bound.
All broker-generated errors and standalone-scanner diagnostics then cross the
same plain-text normalizer with a 4 KiB ceiling before stderr reaches either a
terminal or the Omarchy process collector. Raw flag-parser errors are also
suppressed in favor of this path. The broker bound covers strict-decoder errors
that can quote hostile JSON field names; UI-side truncation is not treated as a
process-memory control.
Scanner-level limits currently include 10,000 entries,
32 directory levels, 2 MiB per source file, 32 MiB total retained source, 64 MiB
per ELF file, and 128 MiB total ELF input. Source and binary budgets are
independent. Directory enumeration itself is incremental and retains at most
the remaining file-count budget plus one overflow sentinel. If a directory
exceeds that remaining budget, the scanner omits that directory as a unit and
adds a `max-files` limitation instead of materializing the full listing or
choosing a filesystem-order-dependent subset. Enforced limits are included in
scan metadata and must match the broker's compiled policy.

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

The test is run both normally and with Go's race detector. Additional tests
verify the live systemd scope from inside its cgroup, reject missing, unlimited,
or weaker cgroup controls, trigger real memory and task exhaustion, terminate a
scanner that exceeds wall time, reject scanner output beyond its bound, deny a
nested user namespace, and prove host session sockets are absent. A separate
diagnostic-overflow probe writes beyond the stderr bound and then sleeps; the
test proves the broker cancels promptly rather than waiting for stdout or the
wall deadline.

## Non-claims

Bubblewrap is a policy construction tool, not a security guarantee by itself.
These tests demonstrate behavior on supported Linux environments; they do not
prove the absence of kernel, Bubblewrap, Go runtime, or scanner vulnerabilities.
