# Deterministic scanner sandbox policy

Status: implemented foundation; not yet release-approved.

## Boundary

The trusted broker resolves an installed plugin ID, opens the scanner and target
as stable file descriptors, verifies their identity and type, and gives those
descriptors to Bubblewrap. Target-controlled text never enters a Bubblewrap
option. Endpoint symlinks are rejected.

The sandbox is built from an empty mount namespace. It contains only:

- the pinned static scanner at `/app/plug-prejudice`, read-only;
- the pinned selected plugin at `/target`, read-only; and
- a private ephemeral `/tmp`.

The scanner emits its bounded JSON report through a pipe. It has no host-backed
writable output directory.

## Namespace and process policy

The broker requires Bubblewrap and fails closed if it is unavailable. The
current arguments establish:

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

The broker imposes a 30-second wall-clock timeout, a 16 MiB report limit, and a
64 KiB diagnostic limit. Scanner-level limits currently include 10,000 entries,
32 directory levels, 2 MiB per source file, 32 MiB total retained source, 64 MiB
per ELF file, and 128 MiB total ELF input. Source and binary budgets are
independent. Additional systemd memory, CPU, and process accounting remains a
release requirement and is not claimed by the current implementation.

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

The test is run both normally and with Go's race detector. Tests of wall-clock
termination, output exhaustion, nested namespaces, session sockets, memory/CPU
limits, and systemd composition are still required before release.

## Non-claims

Bubblewrap is a policy construction tool, not a security guarantee by itself.
These tests demonstrate behavior on supported Linux environments; they do not
prove the absence of kernel, Bubblewrap, Go runtime, or scanner vulnerabilities.
