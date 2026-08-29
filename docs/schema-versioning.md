# Report schema versioning

Status: proposed version-2 compatibility contract; human review required before
the first public release.

The scanner's JSON report is a trust boundary, not an informal serialization.
Producers emit exactly one schema version and consumers accept only versions
they explicitly understand. Duplicate or unknown fields, unknown enum values,
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

## Golden fixture

`internal/report/testdata/report-v2.0.0.json` is a representative conforming
document covering every top-level collection, fact/inference findings,
dedicated unknown records, structured provenance, typed evidence links,
inventory-derived coverage dispositions, limitations, errors, and
sandbox resource metadata. It
is compatibility evidence, not a claim that every possible document shape is
represented. Focused validator tests remain authoritative for invalid cases.
