# Report contract

Status: versioned development contract; not yet release-stable.

The scanner emits one canonical, HTML-escaped UTF-8 JSON object no larger than
16 MiB. It validates and bounded-encodes that exact representation in memory
before writing any destination bytes. The in-memory producer validator rejects
invalid UTF-8 in every serialized string and map key before `encoding/json`
can replace bytes. The trusted broker accepts no malformed UTF-8, invalid
UTF-16 surrogate escapes, duplicate members, case aliases,
unknown exact member names, excessive nesting, trailing values, unsupported schema versions, invalid enum values,
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
version, and evidence source. Every evidence location names a bounded declared
input. Local source and inventory-metadata evidence must name an actually
retained target inventory path; external Omarchy evidence must name its
separate declared pinned audit input and cannot impersonate the target. The
target input has fixed ID `input-target`, type `target-inventory`, format
`plug-prejudice-inventory`, and version `2.0.0`; exactly one is permitted.
Omarchy inputs use the pinned `omarchy-plugin-audit` / `pr8439-732b104`
contract. Local evidence must name the trusted deterministic analyzer and exact
scanner version; Omarchy evidence must name `omarchy/plugin-audit` and the
input's exact version. Provenance identifies an asserted producer, not truth. Inventory paths are unique canonical POSIX
target-relative labels. `target.fileCount` equals
the inventory length. Every finding has at least one valid evidence location;
every resource has valid evidence and names an existing originating operation.
Optional limitation/error paths, when present, obey the same canonical target-relative
path rule. These invariants are checked after strict JSON decoding and before
presentation.

Evidence-input digest fields have separate meanings. `documentSha256` is the
lowercase SHA-256 of the exact pinned external document bytes parsed by the
trusted importer. It establishes document identity only; it neither identifies
the plugin snapshot described by that document nor proves the external
analyzer correct. `subjectRootDigest` identifies the target snapshot an
external format claims to have analyzed. The validator accepts that field only
for an explicitly supported format whose trusted importer obtains it from the
format, and requires it to equal the independently recomputed
`target.rootDigest`. The mandatory `input-target` declaration uses
`subjectRootDigest` to repeat that independently recomputed inventory root and
does not use `documentSha256`.

An inventory entry marked `inspected` has exactly one canonical lowercase
SHA-256 digest and no skip reason; an uninspected entry has no content digest.
Link targets belong only to symlink entries. Parsed binary metadata belongs
only to an inspected entry identified as ELF. Evidence may omit line numbers,
but a line end cannot appear without a positive line start and cannot precede
that start. `target.readBytes` and `target.binaryBytes` exactly equal the sizes
of inspected non-ELF and ELF inventory entries respectively; the validator
reconciles both totals without overflowing on hostile sizes.

Every JSON-visible string and map key is independently bounded by encoded JSON
size. A structural pre-pass rejects duplicate members and nesting deeper than
64 levels before typed decoding. The validated object graph is also bounded: at most 10,000 inventory entries,
20,000 operations, resources, findings, and limitations respectively, 680,000
typed relationships (20,000 resource origins + 320,000 finding support +
320,000 unknown-operation support + 20,000 comparisons), and 10,000 scan
errors. The deterministic producer uses a
lower 20,000-relationship budget. These are rejection limits, not silent
truncation rules.
They constrain a compromised or buggy producer before its graph reaches the
panel. The scanner's own analysis-production budget remains a separate required
defense so a hostile target cannot waste work before serialization; the
recommended design is recorded in [ADR 0005](decisions/0005-analysis-production-budget.md).

Canonical encoding operates on a copy. It sorts the non-semantic collections:
evidence inputs by ID; inventory by path; operation, resource, finding, and
unknown nodes by full internal identity; relationships by complete typed tuple;
limitations and errors by documented tuples; manifest kinds and ELF library,
symbol, extracted-string, URL, and capability sets lexically; finding/unknown
evidence by evidence tuple; finding related IDs, unknown affected-operation
IDs, and suppressed-rule IDs lexically; and review reasons by deterministic
priority and stable reference/title. JSON map keys use the standard lexical
ordering of Go's JSON encoder. Operation arguments retain call position,
unknown origins retain data-flow trace order, and archive entries retain
package order; changing those semantic sequences changes canonical bytes. Scan
start/completion timestamps are observations and therefore intentionally vary.
Deterministic ordering supports report comparison and audit but does not turn a
scan into a reproducible or atomic filesystem snapshot.

## Top-level sections

- `scan`: scanner/policy versions, UTC timestamps, whether the trusted broker
  established containment, and exact memory/swap/task/CPU/wall-time limits.
- `target`: display identity, bounded inventory totals, content digest, and any
  deterministically parsed Omarchy manifest.
- `evidenceInputs`: bounded typed declarations separating the retained target
  inventory from pinned external audit documents.
- `inventory`: files and deliberately skipped inputs, including inspected ELF
  metadata without executing binaries and bounded archive member metadata
  without extracting payloads.
- `operations`: commands and other observable actions extracted from source.
- `resources`: network, filesystem, credential, and persistence targets tied to
  originating operations.
- `findings`: contextual security consequences with `fact` or `inference` claim type, severity,
  confidence, scope, evidence, and deterministic provenance.
- `unknowns`: the only representation for unresolved behavior, with a reason, bounded textual origins,
  affected operations, withheld rule IDs, evidence, and provenance; unknowns
  do not carry severity.
- `relationships`: typed deterministic edges from resources and
  fact/inference findings and dedicated unknown records to supporting
  operations, plus separately
  validated corroboration, disagreement, or duplication edges when multiple
  evidence sources exist.
- `limitations`: analysis coverage that could not be completed safely.
- `errors`: bounded per-input failures that prevent a complete result.
- `review`: validator-recomputed security impact, evidence confidence,
  retained-artifact analysis coverage, unknown behavior, evidence-node counts,
  and bounded main reasons. The dimensions and denominator are defined in ADR
  0018 and never form a safety score.

Optional Omarchy audit nodes retain `omarchy-audit` provenance. `corroborates`
is restricted to operation/operation or resource/resource observations with
the same validated semantic subject, one local producer and one distinct
external producer. `duplicates` requires the same kind, semantic payload, and
source/analyzer boundary. `disagrees-with` is restricted to an operation or
resource observation and a fact, informational, high-confidence, unknown-scope
Omarchy coverage-difference finding. Its single evidence record and
analyzer/version/source provenance must equal the retained source observation
(apart from the exact comparison rule ID), and its `coverage` basis subject
must equal the reconstructed source subject. Exact matches
may be connected with `corroborates`; retained-set differences use
`disagrees-with` plus an informational coverage finding. Neither edge asserts
correctness or safety: a disagreement means only that one source retained the
observation while the compared source retained no matching observation. The
current pinned Omarchy PR #8439 format does not supply a target snapshot root.
Its trusted importer calculates `documentSha256` from the exact pinned audit
bytes, but the exact source-bound `external-input-unbound` unknown remains
mandatory regardless of that document digest. Consequently a current-format
Omarchy input cannot produce a `complete` report. A future external format may
omit this unknown only after its explicit format policy permits
`subjectRootDigest` and the supplied value matches the independently recomputed
target inventory root. A document digest is never copied or interpreted as a
subject digest, and neither digest proves that the external analyzer was
correct.

`target.rootDigest` is mandatory, including for an empty inventory. The
producer and accepting validator share one algorithm, and the validator
independently recomputes the value rather than trusting either serialized
digest field. SHA-256 receives a domain string and record count followed by
records in path order. Each record encodes path, kind, mode, unsigned size,
retained SHA-256, link target, and skip reason; every variable field is an
unsigned 64-bit big-endian byte length followed by its UTF-8 bytes. NUL in a
filesystem observation field is rejected. Analysis dispositions, extracted
metadata, findings, and summaries do not affect this target-observation digest.
The exact digest is repeated by the sole target evidence input. It binds the
bytes actually retained for inspection and makes serialized inventory changes
visible; it does not
hash skipped file content, establish an atomic filesystem snapshot, or prove
that the target has not changed since the scan.

Each inventory record carries one authoritative analysis disposition:
`not-applicable`, `analyzed`, `partial`, or `unanalyzed`. Every disposition is
counted exactly once: `retainedUnits = totalUnits + excludedUnits`, while
`totalUnits = analyzedUnits + partialUnits + unanalyzedUnits`. Every exclusion,
partial unit, and unanalyzed unit requires a reason. ELF and bounded archive
metadata cannot claim complete semantic behavior analysis. Every retained ELF
requires its own `native-behavior` unknown citing `input-target` and that exact
ELF path, with local deterministic source/inventory provenance and runtime or
unknown scope; external evidence and repository-tooling uncertainty cannot
satisfy it. Coverage is recomputed from these records;
inventory retention alone is not semantic analysis. The validator can enforce
artifact classes visible in serialized metadata, but cannot rediscover every
language without retained bytes.

Arrays are always emitted as arrays rather than `null`. A `complete` report has
no unknowns, limitations, errors, or excluded retained units and requires
complete coverage (or an actually empty denominator and inventory). `incomplete` means the visible findings
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

- `claim`: `fact` or `inference`. Unknown behavior is a structurally separate
  record without severity and cannot be represented by relabelling a finding.
- `severity`: potential contextual impact—`critical`, `high`, `medium`, `low`,
  or `informational`.
- `confidence`: certainty in the extraction or conclusion—`high`, `medium`, or
  `low`.
- `scope`: `runtime`, `repository-tooling`, or `unknown`.

These dimensions must not be collapsed into a numeric safety score. A report
never establishes that a plugin is safe.

Dedicated unknown records use a reason (`dynamic-value`,
`unsupported-syntax`, `parser-failure`, `budget-exhaustion`,
`unreachable-source`, `native-behavior`, `unresolved-data-flow`, or the
dedicated `external-input-unbound`) rather than
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
