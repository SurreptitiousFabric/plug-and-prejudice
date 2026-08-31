# Independent human review guide

This document turns the release-blocking human gates into reproducible review
work. Automated checks can prepare evidence, but cannot approve their own trust
boundaries. A reviewer must be independent of the implementation being
approved and record specific observations rather than a general “looks good.”

No review task may execute, source, import, or evaluate a target plugin. Use
only inert fixtures read as data. Do not include credentials, private plugin
source, live malware, or personal configuration in retained evidence.

The GitHub issue for each review track must be a self-contained entry point. It
links every named ADR, guide section, implementation area, focused pull request,
safe command, and evidence template. Security-review links use a commit snapshot
so their content does not move during review; the reviewer separately records
the exact candidate commit on which the conclusion is based.

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

### What this track is asking

In plain English: check that hostile file bytes cannot make a parser run target
code, consume unbounded resources, or claim more than the recognized syntax
proves. Then check that the correlation stage does not turn separate facts into
an invented story about runtime behavior.

A **grammar boundary** is the documented limit around file selection, syntax,
allowed claims, failure behavior, and resource use. The
[parser and grammar boundary map](parser-boundaries.md) defines those five terms,
lists every supported input, and links each boundary to its design record,
implementation, tests, limits, and dependency origin.

**Dependency provenance** means being able to trace parser code and generated
grammar data to an exact module version, authenticated module bytes, upstream
grammar repository and commit, license, production linkage, and review result.
Start with the [dependency audit](dependencies.md#production-go-dependencies),
[`go.mod`](../go.mod), [`go.sum`](../go.sum), and
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md). The boundary map records
the exact Python and JavaScript grammar commits and the command that reads their
authenticated upstream lock.

### Review map

Do not read “ADRs 0010–0019” as an unexplained bundle. The
[ADR index](decisions/README.md) gives a one-sentence purpose and direct link for
every record. For this track, use this map:

| Area | Design and behavior | Implementation and evidence |
|---|---|---|
| Shell, Python, and JavaScript parsing | [ADR 0002](decisions/0002-python-javascript-parser-boundary.md), [shell rules](analysis-rules.md#shell-syntax), [Python/JavaScript rules](analysis-rules.md#python-and-javascript-syntax-tree-boundary), [parser dependencies](dependencies.md#production-go-dependencies) | [`shell.go`](../internal/analyze/shell.go), [`treesitter.go`](../internal/analyze/treesitter.go), adjacent tests, [`verify-parser-footprint.sh`](../scripts/verify-parser-footprint.sh), [`verify-parser-oracles.sh`](../scripts/verify-parser-oracles.sh) |
| QML command extraction and literal flow | [QML rules](analysis-rules.md#qml-process-extraction), [ADR 0019](decisions/0019-bounded-qml-literal-flow.md) | [`qml.go`](../internal/analyze/qml.go), [`qml_flow.go`](../internal/analyze/qml_flow.go), adjacent tests |
| Desktop, systemd, and Hyprland configuration | [ADRs 0011–0013](decisions/README.md), matching sections in the [rule catalogue](analysis-rules.md) | [`desktop.go`](../internal/analyze/desktop.go), [`systemd.go`](../internal/analyze/systemd.go), [`hyprland.go`](../internal/analyze/hyprland.go), adjacent tests |
| Correlations and indirect reachability | [ADR 0008](decisions/0008-correlation-engine.md), [ADR 0014](decisions/0014-indirect-script-reachability.md) | [`correlations.go`](../internal/analyze/correlations.go), [`installed_artifacts.go`](../internal/analyze/installed_artifacts.go), [`reachability.go`](../internal/analyze/reachability.go), adjacent tests |
| Archive and ELF readers | [ADR 0015](decisions/0015-archive-metadata-inventory.md), [ADR 0016](decisions/0016-bounded-elf-metadata.md) | [`inventory.go`](../internal/inventory/inventory.go), [`binary.go`](../internal/analyze/binary.go), adjacent tests |
| Facts, inferences, unknowns, provenance, and summary wording | [ADRs 0009, 0010, and 0018](decisions/README.md), [report contract](report-contract.md), [severity model](severity-model.md) | [`internal/report/`](../internal/report), provenance and scenario tests in [`internal/analyze/`](../internal/analyze) |
| Optional Omarchy audit comparison | [ADR 0017](decisions/0017-optional-omarchy-audit-evidence.md), [rule catalogue](analysis-rules.md#optional-omarchy-audit-evidence) | [`omarchy_audit.go`](../internal/analyze/omarchy_audit.go), adjacent tests |

Read the relevant rows above, the [deterministic rule playbook](detection-rules.md),
and the source and tests they link. A reviewer may split the work into recorded
subsections, but the final Track B conclusion must state which rows were
actually covered.

### What to confirm

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

### Minimum reproducible checks

From a clean checkout of the commit being reviewed, run:

```bash
export GOFLAGS='-tags=grammar_subset,grammar_subset_python,grammar_subset_javascript'
go mod verify
scripts/verify-production-dependencies.sh
go test -race ./internal/analyze
scripts/verify-parser-footprint.sh
scripts/verify-parser-oracles.sh
```

Run reviewed fuzz campaigns separately and record each target, duration, and
result. The [development guide](development.md#headless-checks) gives a safe
example. Independently inspect representative benign and hostile fixtures as
bytes only. Do not invoke fixture paths with a shell, language runtime, archive
extractor, desktop/systemd/Hyprland loader, QML engine, or ELF loader.

The parser-oracle script is a narrow exception only for the trusted synthetic
Python and JavaScript samples created inside that script. Verify this property
before running it; target or fixture bytes must never enter those runtimes.

Record findings and the track-limited conclusion with the
[review evidence template](review-evidence/TEMPLATE.md). “Approve” means only
that the named Track B boundaries were reviewed at the recorded commit; it is
not a claim that the product or a plugin is safe.

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
