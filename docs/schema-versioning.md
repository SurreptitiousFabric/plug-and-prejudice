# Report schema versioning

Status: proposed version-2 compatibility contract; human review required before
the first public release.

The scanner's JSON report is a trust boundary, not an informal serialization.
Producers emit exactly one schema version and consumers accept only versions
they explicitly understand. Member names are exact and case-sensitive.
Malformed Unicode in decoded bytes or producer-side Go strings, duplicate or unknown fields, unknown enum values,
excessive nesting, trailing JSON,
and unsupported schema versions fail closed.

## Version number

`schemaVersion` uses `MAJOR.MINOR.PATCH`, independently of the scanner release
version.

- **Patch** changes clarify documentation or tighten validation without
  changing any conforming JSON document. They do not add fields or enum values.
- **Minor** changes are additive for consumers deliberately written to tolerate
  them. Because the version-2 Omarchy consumer rejects unknown fields and enum
  values, it must be updated and tested before it accepts a new minor version.
- **Major** changes remove or rename fields, change types or meanings, weaken an
  invariant, or otherwise make an old document misleading under new rules.

Scanner releases may improve detections, explanations, ordering, or policy
versions without changing the report schema. Internal finding IDs and prose are
not a stable API. Schema-2 public `PP-` references are stable for the same node
kind and deterministic internal ID; their derivation and typed relationship
meaning are part of this contract.

Canonical ordering of evidence, limitations, and scan errors compares their
typed fields individually rather than joining hostile strings with a delimiter.
It is deterministic for all schema-valid Unicode text, including embedded
U+0000. Evidence line positions are compared numerically.

## Compatibility process

Any schema change must:

1. state the old and new interpretation and its security consequence;
2. update the Go producer, strict validator, UI consumer, contract, and golden
   fixtures in the same reviewed change;
3. add acceptance and rejection tests at the version boundary;
4. preserve a clear unsupported-version error rather than partially rendering;
5. define migration behavior before removing support for an accepted version;
   and
6. receive human review as both a report-validation and hostile-rendering
   boundary change.

There is no automatic downgrade, field stripping, best-effort rendering, or
network schema lookup. A report is self-contained and local.

## Evidence-input digest semantics

Schema 2.0.0 keeps external document identity separate from target-snapshot
identity. `documentSha256`, when present, is the lowercase SHA-256 calculated
by the trusted importer from the exact pinned external bytes it parses. It does
not bind those bytes to `target.rootDigest`. `subjectRootDigest` names the
snapshot an external format claims to cover and establishes binding only when
that exact format/version is listed by the accepting policy as supplying the
field and the value equals the validator's independently recomputed target
root. Producers cannot select arbitrary format metadata to opt into that
meaning.

The current `omarchy-plugin-audit` / `pr8439-732b104` policy requires a
calculated document SHA-256, does not accept `subjectRootDigest`, and therefore
always requires the dedicated external-input binding unknown. The target
inventory declaration instead requires `subjectRootDigest` to equal the
recomputed Plug & Prejudice inventory root. Neither field authenticates an
analyzer or proves its observations correct.

Schema 2.0.0 keeps assertion identity independent from evidence origin.
`analyzer` and `analyzerVersion` identify the software that asserted a record;
`evidenceSource` and each evidence item's `inputId` identify the evidence class
and concrete declared input supporting it. A raw Omarchy observation is
asserted by `omarchy/plugin-audit`. A Plug & Prejudice binding, coverage, or
comparison-budget conclusion may cite that same Omarchy input but is asserted
by the deterministic scanner. This provenance is structural attribution, not
cryptographic authentication or proof of truth. Typed relationships remain
validator-derived graph edges without separate provenance in this schema.

The coverage-comparison rule and coverage-difference category are reserved as
one paired schema shape. Such a finding is accepted only when it is the
destination of exactly one fully validated `disagrees-with` edge from a
retained operation or resource. The edge states only that one evidence source
retained the observation while the compared source retained no exact match; it
does not establish that either analyzer is wrong. The finding remains asserted
by Plug & Prejudice when its supporting observation came from Omarchy.

Resource comparison identity in schema 2.0.0 is the explicitly versioned,
injective `resource-subject/v1` representation of the exact `(kind, access,
value)` triple. Each component carries its decimal UTF-8 byte length before its
bytes; delimiter joining is not accepted. Consequently embedded NUL, control,
escape-like, prefix/suffix, and Unicode text cannot move data between fields or
make distinct triples compare equal. This is structural equality rather than a
probabilistic hash, and no additional resource fields participate in the
subject.

## Golden fixture

`internal/report/testdata/report-v2.0.0.json` is a representative conforming
document covering every top-level collection, fact/inference findings,
dedicated unknown records, structured provenance, typed evidence links,
inventory-derived coverage dispositions, limitations, errors, and
sandbox resource metadata. It
is compatibility evidence, not a claim that every possible document shape is
represented. Focused validator tests remain authoritative for invalid cases.
