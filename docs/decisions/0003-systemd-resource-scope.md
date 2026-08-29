# 0003: Systemd resource scope composition

- Status: proposed; implementation pending human security review
- Date: 2026-08-27

## Context

Bubblewrap isolates namespaces and mounts but does not impose cgroup memory,
task, or CPU ceilings. Scanner-local byte limits do not protect against parser
bugs, allocator amplification, runaway threads, or other implementation faults.
ADR 0001 already accepts systemd resource control as part of the initial
containment architecture.

## Decision

Before resolving or opening a target, the broker re-executes its already-running
inode through `/proc/<pid>/exe` in a randomized transient user scope. The scope
sets:

- `MemoryMax=256 MiB`;
- `MemorySwapMax=0`;
- `TasksMax=64`;
- `CPUQuota=100%` across all tasks;
- `RuntimeMaxSec=35s`; and
- memory/task accounting enabled explicitly.

The scoped broker reads its unified cgroup-v2 path from `/proc/self/cgroup` and
directly verifies `memory.max`, `memory.swap.max`, `pids.max`, and `cpu.max` are
at least as strict as policy. Through the pinned `/usr/bin/systemctl` inode it
also queries the exact randomized unit and rejects a missing, unlimited, or
weaker `RuntimeMaxUSec`. It then lowers `RLIMIT_CORE` to zero and
`RLIMIT_NOFILE` to at most 256. Only after those checks does it resolve the
installed plugin and open the target/scanner descriptors for Bubblewrap.
The broker opens fixed `/usr/bin/systemd-run`, `/usr/bin/systemctl`, and `/usr/bin/bwrap` paths with
Linux `openat2`, rejecting symlinks and magic links, then verifies each pinned
descriptor is a root-owned, executable, non-group/world-writable ELF regular file.
Execution uses `/proc/self/fd/N`, which Linux resolves to that open inode during
`execve`; a pathname or mount replacement after validation cannot substitute a
containment tool. This relies on Linux procfs being mounted and available to the
trusted broker. `systemd-run` and `systemctl` receive a fixed environment rather
than the user session environment. The broker derives `/run/user/<euid>`, opens
it without symlink traversal, and verifies that it is an euid-owned directory
with no group/world permissions before supplying it as `XDG_RUNTIME_DIR`.
Locale, pager, color, and URL rendering are fixed; loader, D-Bus override,
configuration, Go-runtime, and other inherited variables are absent. Inherited
`PATH` is never used to choose either executable.

Bubblewrap retains the independent 30-second context deadline. The extra five
seconds on the outer scope allow ordinary broker validation and teardown while
still bounding failures outside the child timeout.

Go subprocess waiting and both bounded pipe readers run concurrently. A
two-second `WaitDelay` bounds pipe closure after cancellation even when a
descendant retains one or both output descriptors. When the scoped broker
exits, the outer process uses the trusted systemd interface to request SIGKILL
for all remaining processes in the exact scope, then polls that scope's
validated cgroup `populated` state until it observes zero (or collection) under
a three-second deadline. Acceptance of the asynchronous kill request alone is
not treated as completion evidence.
The verified scope runtime remains the final independent bound if inner cleanup
does not cooperate.

The report records the exact enforced policy. The trusted broker rejects a
scanner report whose resource metadata differs from its compiled policy.

## Rationale

The 256 MiB ceiling accommodates the scanner's separate 32 MiB source and
128 MiB ELF read budgets, bounded report output, Go runtime, and parser overhead
without granting unbounded memory. Sixty-four tasks leave room for the broker,
Bubblewrap, Go runtime threads, and kernel helpers while limiting fork/thread
storms. A 100% aggregate quota permits one CPU of sustained work and avoids a
host-wide CPU denial of service. Swap is disabled so the memory ceiling remains
meaningful. Core dumps are disabled because they can retain hostile or private
process memory outside the intended output path.

## Alternatives rejected

- Scanner-only counters cannot contain allocator, parser, or runtime defects.
- Shell `ulimit` would add a shell execution boundary and lacks cgroup memory
  accounting.
- A transient service complicates structured stdio and process ownership;
  systemd 261 also rejects `--pipe` with scope mode. A synchronous scope inherits
  clean stdout/stderr under `--quiet`.
- Passing pinned target descriptors through `systemd-run` was rejected because
  descriptor preservation would become another uncertain boundary. Re-entering
  the broker before descriptors are opened avoids it.
- Giving Bubblewrap access to the user systemd bus would violate the sandbox's
  session isolation.
- Killing only Bubblewrap cannot prove descendant teardown when a hostile child
  retains pipes; the outer broker therefore cleans the authoritative scope.

## Consequences and residual risk

Scanning now requires a working systemd user manager and cgroup v2 in addition
to Bubblewrap; failure is explicit and closed. The user-session broker retains
the authority needed to ask the user manager for its own scope. Kernel,
systemd, and cgroup implementation bugs remain out of scope. Resource ceilings
reduce denial-of-service impact but cannot prove scanner correctness.
The broker assumes it starts in the real host user and mount namespaces; an
attacker who already controls those namespaces could substitute the apparent
`/usr`, `/run`, procfs, or cgroupfs view and is outside this plugin-content
review boundary.
