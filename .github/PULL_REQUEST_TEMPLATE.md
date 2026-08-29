## What changed

Describe the user-visible or trust-boundary outcome and the evidence supporting
it. Link any required decision record.

## Security reasoning

- What hostile input reaches this change?
- Which fact, inference, or unknown claims change?
- What remains deliberately unresolved?
- Does this alter execution, filesystem, network, sandbox, report-rendering,
  dependency, packaging, update, or disclosure boundaries?

## Verification

List the exact checks run and their results. Do not state that the reviewer or
a reviewed plugin is safe merely because checks passed.

## Review checklist

- [ ] Target-plugin code is treated only as inert data and is never executed.
- [ ] Findings remain evidence-backed; benign and ambiguous cases are tested.
- [ ] New limitations are explicit and incomplete analysis is not presented as complete.
- [ ] Hostile strings remain bounded and inert across report and UI boundaries.
- [ ] Dependencies and trust-boundary changes have an approved decision and focused review.
- [ ] Documentation describes behavior, residual risk, and contributor verification.
- [ ] No credentials, private plugin source, personal configuration, or live malware are included.
