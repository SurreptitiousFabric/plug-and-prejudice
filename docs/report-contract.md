# Report contract

Status: versioned development contract; not yet release-stable.

The scanner emits one UTF-8 JSON object. The trusted broker accepts no unknown
fields, trailing values, unsupported schema versions, invalid enum values,
unsafe evidence paths, broken operation references, or contradictory
`complete` status. The standalone scanner validates the complete object before
writing any report bytes; the broker independently decodes and validates it
before presentation. Consumers must reject reports they do not understand.

The [schema versioning policy](schema-versioning.md) defines compatibility,
coordinated change requirements, and the version-2 golden fixture.

Operation, resource, and finding IDs are unique within their collections. Their
hash-derived public `PP-` references are unique across node kinds and are
recomputed rather than trusted by the validator. Typed relationship IDs and
endpoints are unique, bounded, and validated against the originating resource
or finding claim. Structured provenance requires a rule ID, analyzer, analyzer
version, and evidence source. Inventory paths are unique canonical POSIX
target-relative labels. `target.fileCount` equals
the inventory length. Every finding has at least one valid evidence location;
every resource has valid evidence and names an existing originating operation.
Optional limitation/error paths, when present, obey the same canonical target-relative
path rule. These invariants are checked after strict JSON decoding and before
presentation.

An inventory entry marked `inspected` has exactly one canonical lowercase
SHA-256 digest and no skip reason; an uninspected entry has no content digest.
Link targets belong only to symlink entries. Parsed binary metadata belongs
only to an inspected entry identified as ELF. Evidence may omit line numbers,
but a line end cannot appear without a positive line start and cannot precede
that start. `target.readBytes` and `target.binaryBytes` exactly equal the sizes
of inspected non-ELF and ELF inventory entries respectively; the validator
reconciles both totals without overflowing on hostile sizes.

The validated object graph is also bounded: at most 10,000 inventory entries,
20,000 operations, resources, findings, and limitations respectively, 340,000
typed relationships, and 10,000 scan errors. The deterministic producer uses a
lower 20,000-relationship budget. These are rejection limits, not silent
truncation rules.
They constrain a compromised or buggy producer before its graph reaches the
panel. The scanner's own analysis-production budget remains a separate required
defense so a hostile target cannot waste work before serialization; the
recommended design is recorded in [ADR 0005](decisions/0005-analysis-production-budget.md).

For identical retained target bytes, inventory metadata, and policy, analysis
collections and their relationship IDs are emitted in deterministic order;
source-map insertion and input enumeration order must not affect them. Scan
start/completion timestamps are observations and therefore intentionally vary.
Deterministic ordering supports report comparison and audit but does not turn a
scan into a reproducible or atomic filesystem snapshot.

## Top-level sections

- `scan`: scanner/policy versions, UTC timestamps, whether the trusted broker
  established containment, and exact memory/swap/task/CPU/wall-time limits.
- `target`: display identity, bounded inventory totals, content digest, and any
  deterministically parsed Omarchy manifest.
- `inventory`: files and deliberately skipped inputs, including inspected ELF
  metadata without executing binaries and bounded archive member metadata
  without extracting payloads.
- `operations`: commands and other observable actions extracted from source.
- `resources`: network, filesystem, credential, and persistence targets tied to
  originating operations.
- `findings`: contextual security consequences with claim type, severity,
  confidence, scope, evidence, and deterministic provenance.
- `unknowns`: unresolved runtime values with a reason, bounded textual origins,
  affected operations, withheld rule IDs, evidence, and provenance; unknowns
  do not carry severity.
- `relationships`: typed deterministic edges from resources and
  fact/inference/unknown findings and dedicated unknown records to supporting
  operations, plus separately
  validated corroboration, disagreement, or duplication edges when multiple
  evidence sources exist.
- `limitations`: analysis coverage that could not be completed safely.
- `errors`: bounded per-input failures that prevent a complete result.
- `review`: validator-recomputed security impact, evidence confidence,
  retained-artifact analysis coverage, unknown behavior, evidence-node counts,
  and bounded main reasons. The dimensions and denominator are defined in ADR
  0018 and never form a safety score.

Optional Omarchy audit nodes retain `omarchy-audit` provenance. Exact matches
may be connected with `corroborates`; retained-set differences use
`disagrees-with` plus an informational coverage finding. Neither edge asserts
correctness or safety. The pinned PR #8439 format lacks a target digest, so an
imported report also requires a snapshot-binding unknown even after manifest ID
matching.

`target.rootDigest`, when present, is exactly 64 lowercase hexadecimal
characters representing SHA-256 over deterministically ordered inventory
metadata, retained content hashes, link targets, and skip reasons. It binds the
bytes actually retained for inspection and makes omissions visible; it does not
hash skipped file content, establish an atomic filesystem snapshot, or prove
that the target has not changed since the scan.

Arrays are always emitted as arrays rather than `null`. A `complete` report has
no unknowns, limitations, or errors. `incomplete` means the visible findings
remain useful but are not exhaustive and must contain at least one unknown,
limitation, or scan error explaining why. `error` is reserved for a structured scan result that
could not complete and must contain at least one scan error; broker or
containment failures are not converted into a successful report.

The top-level collections, manifest `kinds`, manifest `entryPoints`, and ELF
library, import, string, URL, and capability collections are structurally
required to be arrays or objects even when empty;
JSON `null` is rejected. Parsed binary metadata must describe an inspected
regular ELF and include its format, class, byte order, machine, type, bounded
collections, and privilege flags. Archive metadata is accepted only on inspected non-ELF regular
files and contains a bounded non-null entry array, format, completeness flag,
and exact retained declared-size sum. Member paths are hostile labels and may
intentionally be absolute or traversal-style evidence; they are never host
paths to open. Invalid plugin manifest values remain visible as hostile facts
and are reported by deterministic manifest findings rather than normalized by
the report validator.

## Independent dimensions

- `claim`: `fact`, `inference`, or `unknown`.
- `severity`: potential contextual impact—`critical`, `high`, `medium`, `low`,
  or `informational`.
- `confidence`: certainty in the extraction or conclusion—`high`, `medium`, or
  `low`.
- `scope`: `runtime`, `repository-tooling`, or `unknown`.

These dimensions must not be collapsed into a numeric safety score. A report
never establishes that a plugin is safe.

Dedicated unknown records use a reason (`dynamic-value`,
`unsupported-syntax`, `parser-failure`, `budget-exhaustion`,
`unreachable-source`, `native-behavior`, or `unresolved-data-flow`) rather than
a severity. Their origins are explicitly evidence locations, not proof of
runtime control flow. See [ADR 0010](decisions/0010-explicit-unknown-behavior.md).
See the [severity model](severity-model.md) for level meanings, contextual
examples, and change requirements.

## Presentation boundary

All strings are hostile. A UI must display them only as plain text, normalize
control characters, bound rendered lengths and collection counts, and never
interpret them as QML, HTML, Markdown, terminal escapes, URLs to open, or shell
commands. Evidence paths are target-relative labels, not authority to open an
arbitrary host path.

The canonical field definitions currently live in
`internal/report/report.go`; `internal/report/validate.go` is the accepting
validator. A machine-readable JSON Schema will be generated and frozen as part
of the release-stability review rather than allowed to drift during early
analysis development.
