# Independent human review guide

This document turns the release-blocking human gates into reproducible review
work. Automated checks can prepare evidence, but cannot approve their own trust
boundaries. A reviewer must be independent of the implementation being
approved and record specific observations rather than a general “looks good.”

No review task may execute, source, import, or evaluate a target plugin. Use
only inert fixtures read as data. Do not include credentials, private plugin
source, live malware, or personal configuration in retained evidence.

## Evidence record

For every review, record:

- reviewer GitHub identity and date;
- exact commit SHA and whether the tree was clean;
- architecture, OS, kernel, Go, systemd, Bubblewrap, Pacman, Omarchy, and
  Quickshell versions when relevant;
- files and ADRs inspected;
- exact commands run and retained output location;
- each invariant confirmed or contradicted;
- findings with severity and concrete file/line evidence;
- disposition of every finding; and
- an explicit approve/reject conclusion limited to that review track.

Approval means the named boundary was reviewed at that exact commit. It is not
a claim that the product or any inspected plugin is safe.

## Track A: containment and selected-tree boundary

Read ADRs 0003 and 0006 plus:

- `internal/sandbox/`, `internal/resource/`, and `internal/trustedexec/`;
- broker target selection and descriptor passing;
- inventory descriptor-relative opens and mount-ID checks;
- `docs/sandbox-policy.md` and `docs/threat-model.md`.

Confirm:

- target paths are resolved beneath the approved root with no symlink,
  magic-link, cross-mount, or parent-swap escape;
- the already-open descriptor, not a re-resolved hostile path, enters the
  sandbox;
- no home, credentials, session sockets, host process namespace, or network
  namespace enters deterministic analysis;
- fixed trusted executables are regular, root-owned, non-symlink, non-writable,
  version-matched, and inode-pinned;
- CPU, memory, swap, tasks, file descriptors, output, and elapsed time fail
  closed; and
- nested mounts and unsupported kernel guarantees fail closed or become an
  explicit rejected scan, never a weaker sandbox.

Run at minimum `go test -race ./internal/sandbox ./internal/inventory
./internal/resource ./internal/trustedexec` and the authorized live containment
cases described in `docs/development.md`. Include positive, negative, race,
escape, and denial-of-service observations.

## Track B: hostile parsers and correlation semantics

Read ADRs 0002, 0008, and 0010–0019 plus `internal/analyze/`, parser dependency
locks, `docs/analysis-rules.md`, `docs/detection-rules.md`, and
`docs/severity-model.md`.

Confirm:

- no target language runtime, systemd/desktop interpreter, archive extractor,
  ELF loader, shell, or target command is invoked;
- every accepted grammar is narrower than the claim it produces;
- malformed, ambiguous, duplicate, dynamic, cyclic, nested, and over-budget
  forms become neutral facts, limitations, or unknowns rather than guesses;
- correlations cite all supporting operations and distinguish exact flow from
  co-capability;
- explanations do not imply control flow, successful access, installation,
  enablement, activation, execution, or data flow unless established; and
- positive, negative, legitimate, false-positive, hostile, race, deterministic,
  and fuzz cases cover each rule family.

Run `go test -race ./internal/analyze`, both parser-oracle/footprint scripts, and
reviewed fuzz campaigns. Independently inspect representative benign and
hostile fixtures as bytes only.

## Track C: schema, evidence graph, broker, and hostile rendering

Read ADRs 0005, 0007, 0009, 0010, 0017, and 0018 plus:

- `internal/report/`, `internal/boundedjson/`, and `internal/safetext/`;
- scanner/broker JSON production and validation;
- `Panel.qml` and QML load/visual/integration harnesses;
- `docs/report-contract.md`, `docs/schema-versioning.md`, and `docs/ui.md`.

Confirm:

- facts, inferences, unknowns, limitations, and errors cannot be confused;
- every claim has stable evidence references and structured provenance;
- the accepting validator recomputes references, relationships, and summary
  dimensions instead of trusting scanner labels;
- malformed, duplicate, oversized, conflicting, or version-unknown JSON fails
  atomically with no partial report;
- broker output is exactly its validated typed report, not attacker-selected
  bytes; and
- every plugin-controlled field is bounded plain text with no QML, HTML,
  Markdown, URL, terminal-escape, command, or bidi-control interpretation.

Run `go test -race ./internal/report ./internal/boundedjson
./internal/safetext ./cmd/plug-prejudice-broker` and `scripts/test-qml.sh`.
Manually inspect keyboard focus, screen-reader names, error ordering, long text,
bidi/control normalization, and every report section.

## Track D: packaging, CI, SBOM, and provenance

Read ADR 0004 plus `packaging/`, `.github/workflows/`, release scripts,
`docs/dependencies.md`, `docs/releasing.md`, and `docs/release-readiness.md`.

Confirm:

- actions and build tools are immutable/pinned and permissions are minimal;
- release writes and OIDC attestations occur only after both native builds;
- source identity, embedded binary versions, static ELF properties, exact
  package inventory, ownership, and modes are independently verified;
- SBOM components match final binaries/package contents and license evidence;
- checksums, artifact attestations, and maintainer-signed tag bind the same
  approved source and artifacts; and
- install, upgrade, mismatch, and removal use normal Arch/Omarchy mechanisms
  without hooks, self-install, home writes, or hidden network behavior.

Require clean native ARM64 and x86-64 package builds and normal-policy lifecycle
runs on disposable systems. Cross-compilation and the isolated development
Pacman harness are supplementary evidence only.

## Track E: Omarchy UX and accessibility

Review the installed plugin through its fixed broker path on supported Omarchy
themes, scales, and input methods. Do not substitute screenshots or headless
component loading for this human review.

Confirm:

- keyboard-only access reaches every section/action with visible focus;
- pointer targets and scrolling behave at supported scales;
- AT-SPI exposes useful roles, names, state, reading order, and updates;
- color is not the sole carrier of severity, confidence, scope, unknown, or
  error meaning;
- long, empty, incomplete, hostile-control, and high-volume reports remain
  understandable and do not hide failures; and
- wording never calls a plugin safe or turns uncertainty into approval.

Retain theme/scale/input/assistive-technology matrix results and concrete
screens or accessibility-tree excerpts that contain no private plugin data.

## Release decision

The release owner may tag a candidate only when every track has a commit-bound
approval, every finding has a recorded disposition, native release evidence is
retained, and `docs/release-readiness.md` contains no missing or pending gate.
The release owner records the signed tag, checksum manifest, SBOM, attestations,
package inventories, native lifecycle results, and verification commands.
