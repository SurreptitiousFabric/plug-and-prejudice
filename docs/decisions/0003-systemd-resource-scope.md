# 0003: Systemd resource scope composition

- Status: implemented; independent human security review pending
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
at least as strict as policy. It then lowers `RLIMIT_CORE` to zero and
`RLIMIT_NOFILE` to at most 256. Only after those checks does it resolve the
installed plugin and open the target/scanner descriptors for Bubblewrap.
The broker uses fixed `/usr/bin/systemd-run` and `/usr/bin/bwrap` paths only
after verifying each is a root-owned, executable, non-symlink regular file that
is not writable by group or others;
inherited `PATH` cannot substitute a containment tool.

Bubblewrap retains the independent 30-second context deadline. The extra five
seconds on the outer scope allow ordinary broker validation and teardown while
still bounding failures outside the child timeout.

The report records the exact enforced policy. The trusted broker rejects a
scanner report whose resource metadata differs from its compiled policy.

The `--resource-scope` re-entry value is an internal scope identifier, not a
secret capability. Verification binds it structurally to the current process:
the current unified cgroup must have that exact, tightly validated basename and
the four cgroup-exposed limits must be no weaker than policy. This prevents an
ordinary direct invocation from merely asserting that containment exists.
It does not establish which process created the scope.

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

## Consequences and residual risk

Scanning now requires a working systemd user manager and cgroup v2 in addition
to Bubblewrap; failure is explicit and closed. The user-session broker retains
the authority needed to ask the user manager for its own scope. Kernel,
systemd, and cgroup implementation bugs remain out of scope. Resource ceilings
reduce denial-of-service impact but cannot prove scanner correctness.

`RuntimeMaxSec` is a systemd unit property rather than a cgroup-v2 control. The
scoped broker therefore also invokes fixed, root-owned `/usr/bin/systemctl` to
query the live unit's `RuntimeMaxUSec` property, bounds the response and query
time, and rejects missing, unlimited, malformed, zero, or weaker values. The
independent Bubblewrap 30-second deadline remains defense in depth.
