# 0018: Independent review dimensions

- Status: implemented in development tree; independent rubric/UI review pending
- Date: 2026-08-28

## Context

One verdict or numeric risk score collapses consequence, evidence certainty,
analysis completeness, and unresolved behavior. A quiet report can otherwise
look like approval even when the analyzer did not understand the relevant
files.

## Decision

Add a required, validator-recomputed `review` summary with five independent
parts. No field is named safety, trust, approval, clean, or verdict.

### Security impact

Use the highest severity among retained `fact` and `inference` findings.
Unknown-claim findings are excluded and counted under unknown behavior. When
there are no fact/inference findings, the impact level is informational with no
reason; that does not mean safe. Retain up to eight highest-level reasons with
their stable finding references.

### Evidence confidence

The headline is the weakest confidence among the highest-impact reasons. It is
`not-applicable` when no impact reason exists. Separately count high, medium,
and low confidence across all retained operations, resources, findings, and
dedicated unknowns. This is certainty of extraction/conclusion, not confidence
that the plugin is benign.

### Analysis coverage

The denominator is exactly: “retained supported executable, configuration,
archive, and binary artifact files.” Eligible units include the manifest,
supported shell/QML/desktop/systemd/Hyprland/Python/JavaScript sources,
explicitly unsupported source-language files, archives, and ELF binaries.
Ordinary documentation/media are excluded. Fully analyzed units receive one
unit; partial and unanalyzed units receive zero rather than arbitrary fractional
credit. The integer percentage is `floor(analyzed * 100 / total)`.

No percentage is emitted when total is zero. Categories are complete (all),
substantial (at least 80%), partial (1–79%), limited (0%), and not-applicable
(zero denominator). Files omitted before retention are not secretly added to
the denominator; their production/budget limitations independently raise the
unknown-behavior dimension.

### Unknown behavior

Categories are:

- none: no dedicated unknown, limitation, or error;
- low: only unknown-scope/tooling uncertainty or limitations;
- moderate: runtime-scoped unknowns or limitations without a stronger case;
- high: scan errors, parser/budget unknowns, explicit production/budget
  limitations, or runtime unknowns tied to an affected operation.

Reasons prefer errors and high-impact unknowns, then other unknowns and
limitations. Dedicated unknowns retain stable references; errors/limitations
are plainly marked when no stable evidence-node reference exists.

### Counts and reasons

Facts count operation nodes, resource nodes, and fact findings. Inferences
count inference findings. Unresolved behaviors count dedicated unknowns plus
legacy unknown-claim findings. Up to eight main reasons combine the impact and
unknown lists and retain public references where available.

## Validation and presentation

The broker accepts only a summary that the report validator recomputes exactly
from retained nodes. Coverage totals, denominator, category, and percentage are
validated independently. QML applies its own bounded structural checks and
renders dimensions, denominator counts, and reasons only as plain text. Empty
reasons explicitly say they are not a safety claim.

## Residual risk and review gate

File units are intentionally coarse and do not measure path coverage, branch
coverage, semantic completeness within a parser, or runtime reachability.
Highest-impact confidence can hide lower-confidence lower-impact findings, so
the distribution counts remain visible. Categorization thresholds are product
policy and require human review.

Independent review is required for denominator eligibility, partial-unit
treatment, severity/confidence aggregation, unknown rubric, reason selection,
schema migration, hostile rendering, keyboard/scale behavior, and accessible
wording before merge.
