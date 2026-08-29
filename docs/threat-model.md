# Threat model

## Security objective

Help users understand observable plugin behavior without giving inspected code
an execution path or exposing unrelated user data.

The tool cannot prove that a plugin is safe, recover intent from every binary,
or guarantee detection of all malicious behavior.

## Assets

- User credentials, private files, environment, and personal data.
- Integrity and availability of the desktop session and host system.
- Scanner and report integrity.
- Accuracy and provenance of findings.
- Confidentiality of any data considered for later LLM analysis.

## Adversaries and hostile inputs

Assume a target can deliberately contain:

- malformed manifests and parser edge cases;
- symlinks, hard links, special files, deep trees, huge or sparse files;
- path traversal and confusing Unicode names;
- compressed, generated, minified, encoded, or obfuscated content;
- native binaries for the host architecture;
- terminal escapes, QML/HTML/Markdown injection, and prompt injection;
- source designed to exhaust CPU, memory, storage, or output limits;
- Git metadata intended to mislead provenance checks; and
- code that is already running when an enabled plugin is reviewed.

## Trust boundaries

### Target plugin

Untrusted. The scanner may read bounded regular-file content but never execute,
source, import, or evaluate it.

### Scanner

Trusted code exposed to hostile parsers and filesystem structures. It runs in a
Bubblewrap sandbox with a private network, PID, IPC, UTS, and mount view. Only a
read-only target, minimal runtime, private temporary area, and controlled output
are visible.

### Broker

Trusted and unsandboxed enough to construct containment. It must use canonical
paths, fixed arguments, cleared environment, safe file descriptors, and strict
plugin-ID resolution. Target content must never influence Bubblewrap options or
host paths.

The supported higher-assurance path is the independently installed CLI started
from the normal host session. The containment claim assumes the real host user
and mount namespaces and does not authenticate an arbitrary caller's namespace
view. Launch inside an attacker-created namespace with substituted `/usr`,
`/run`, procfs, or cgroupfs is outside the deployment precondition. This is
distinct from hostile plugin files, which are fully in scope as inert static
input. An already-enabled same-user malicious plugin is active session code and
may interfere with the desktop wrapper or user presentation before review.

The broker enters a verified transient systemd user scope before target
resolution. The scope bounds memory, swap, tasks, aggregate CPU, and lifetime;
process rlimits disable core dumps and cap open descriptors. The broker fails
closed if the user manager or cgroup-v2 controls cannot establish and prove the
policy.

Trusted systemd tools receive a validated minimal environment: a checked
`/run/user/<euid>` location plus fixed locale and presentation controls. The
broker does not inherit loader, D-Bus override, systemd override, pager,
configuration, or Go-runtime variables into these executions. Whole-scope
teardown observes the exact cgroup become unpopulated or collected; an accepted
asynchronous kill request alone is not completion evidence.

Plugin listing is also performed only after this verification and is incremental
and bounded. The production scanner and all three containment executables are
root-owned, non-group/world-writable pinned inodes. The selected plugin is
opened descriptor-relatively beneath a pinned plugin root. Scanner traversal is
rooted at that descriptor. A bounded second pass rechecks the complete observed
path set, directory membership, and identity/metadata; detected target mutation
aborts the report.

### Omarchy wrapper

Trusted but hosted in the same unsandboxed `omarchy-shell` process as enabled
plugins. It must remain small. An already-running malicious plugin may tamper
with the desktop or reviewer presentation; the independent CLI is the recovery
and higher-assurance interface.

### Report

Untrusted until schema, type, size, and relationship validation succeeds. Every
plugin-controlled string is rendered as inert plain text with control-character
handling and display limits.

### Dependencies and updates

Dependencies add parser and supply-chain attack surface. Pin direct dependencies,
review transitive changes, retain checksums, generate an SBOM for releases, and
publish signed checksums/provenance where practical. A reviewed plugin report is
bound to exact file hashes and Git state, not merely its name or version claim.

### LLM boundary

No LLM or external network exists in version 1. A future stage must not access
the target or home directory directly and must show the user a redacted outbound
payload before disclosure.

## Primary attack classes and controls

| Attack | Initial controls |
|---|---|
| Target code execution | Scanner has no target-execution or subprocess path; no imports or shell evaluation; empty runtime limits exploit utility |
| Arbitrary file read | Empty filesystem view; only target is read-only mounted |
| Host modification | Dedicated output and temporary areas; read-only runtime; no session sockets |
| Network access | Private network namespace with no shared host network |
| Path escape | Boundary executables and the trusted configured root reject symlink/magic-link traversal; selected-target resolution is beneath the pinned root and rejects mount crossing; nested-path mount handling remains a later selected-tree boundary |
| Parser denial of service | File/depth/byte/output limits; verified systemd memory/swap/task/CPU scope; independent wall timeout; core/file-descriptor rlimits |
| Report injection | Strict JSON schema; plain-text renderer; control-character normalization |
| False reassurance | Explicit limitations; no safe verdict or opaque score |
| False positives | Parsed context, correlated behavior, benign fixtures, separate confidence |
| Update drift | Commit, dirty-state, file-hash, scanner-version, and policy-version binding |

## Residual risks

- Scanner or kernel vulnerabilities may escape containment.
- Two bounded descriptor-rooted passes verify a stable observed tree by
  comparing path membership, device/inode, type, mode, size, link count, mtime,
  ctime, and symlink targets. This is not an atomic filesystem snapshot; a
  complete change-and-revert between observations remains outside the
  guarantee.
- The target bind is read-only but not proven `noexec`; containment does not
  replace the scanner's invariant that target content is never passed to an
  execution API.
- Static analysis can miss generated, encrypted, environment-dependent, or
  semantically complex behavior.
- Binary inventory cannot establish what a native helper will do at runtime.
- An enabled malicious plugin already has user-session authority before review.
- A compromised build/release channel can replace the reviewer itself.
- Root, kernel, package-manager, or systemd-manager compromise can replace
  trusted installed components and is outside the plugin attacker model.
- Launching the broker inside attacker-controlled user/mount namespaces that
  forge the apparent `/usr`, `/run`, procfs, or cgroupfs view is outside the
  supported host-session assumption.

These risks must remain visible in user-facing reports and release documentation.
