# PR #23 second remediation evidence

Status: automated engineering evidence for independent human review; not an
approval and not completion of issue #18.

Starting head: `48492433a2adbcd9795d305872ec34da18434b09`.

The starting head was exercised in a detached worktree. Focused probes
confirmed that it accepted a later case alias overriding `status`, normalized
invalid raw UTF-8, accepted an evidence path absent from inventory, validated
an object whose JSON encoding exceeded 16 MiB, allowed an inspected ELF to be
excluded from a zero denominator, emitted 64-bit display references, used an
accepting relationship ceiling of 660,000 while documentation said 340,000,
and produced different bytes after non-semantic finding reordering. Its
existing comparison test also demonstrated that unrelated finding nodes could
be called corroborating solely because their evidence-source enums differed.

Schema 2.0.0 now performs a UTF-8 and surrogate-aware, reflection-guided exact
member-name pass before strict typed decoding. It declares evidence inputs and
anchors local evidence to retained inventory paths. Coverage reconciles
`retained = semantic denominator + excluded`, makes every exclusion explicit,
and prevents complete status with exclusions. Serialized ELF/archive metadata
cannot claim complete behavior analysis, and ELF behavior requires a dedicated
native unknown.

Public node and edge display IDs use 128 bits of SHA-256. Construction detects
display collisions against full identities, while required relationships are
tracked by complete typed tuples. Comparison edges carry a validated typed
basis and have narrow operation, resource, duplicate, and coverage-difference
shapes.

`report.WriteCanonical` sorts non-semantic collections, recomputes review
summary data, validates the result, and streams the exact HTML-escaped encoding
into a bounded 16 MiB buffer. It writes the caller's destination only after the
complete encoding succeeds.

The residual live-filesystem and containment assumptions belong to PR #22.
This contract validates internal consistency and declared provenance; it does
not prove that any observation is true, that coverage is correct, or that a
plugin is safe. Independent human review remains required.
