# Report contract

Status: versioned development contract; not yet release-stable.

The scanner emits one UTF-8 JSON object. The trusted broker accepts no unknown
fields, trailing values, unsupported schema versions, invalid enum values,
unsafe evidence paths, broken operation references, or contradictory
`complete` status. Consumers must reject reports they do not understand.

## Top-level sections

- `scan`: scanner/policy versions, UTC timestamps, and whether the trusted
  broker established containment.
- `target`: display identity, bounded inventory totals, content digest, and any
  deterministically parsed Omarchy manifest.
- `inventory`: files and deliberately skipped inputs, including inspected ELF
  metadata without executing binaries.
- `operations`: commands and other observable actions extracted from source.
- `resources`: network, filesystem, credential, and persistence targets tied to
  originating operations.
- `findings`: contextual security consequences with claim type, severity,
  confidence, scope, evidence, and deterministic provenance.
- `limitations`: analysis coverage that could not be completed safely.
- `errors`: bounded per-input failures that prevent a complete result.

Arrays are always emitted as arrays rather than `null`. A `complete` report has
neither limitations nor errors. `incomplete` means the visible findings remain
useful but are not exhaustive. `error` is reserved for a structured scan result
that could not complete; broker or containment failures are not converted into
a successful report.

## Independent dimensions

- `claim`: `fact`, `inference`, or `unknown`.
- `severity`: potential contextual impact—`critical`, `high`, `medium`, `low`,
  or `informational`.
- `confidence`: certainty in the extraction or conclusion—`high`, `medium`, or
  `low`.
- `scope`: `runtime`, `repository-tooling`, or `unknown`.

These dimensions must not be collapsed into a numeric safety score. A report
never establishes that a plugin is safe.

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
