# PR #23 third remediation evidence

Status: automated engineering evidence for independent human review; not an
approval and not completion of issue #18.

Starting head: `4c1ab1a8be048369648336977f82bf6f3f553036`.

A detached old-head probe demonstrated that the starting validator accepted a
forged or empty inventory root digest, arbitrary target-input format/version,
and a second target input; normalized invalid in-memory UTF-8 to U+FFFD during
encoding; let an external path-only unknown satisfy target ELF uncertainty;
accepted an undigested external input without visible binding uncertainty;
accepted a magic-category coverage finding whose evidence did not match the
source; treated a same-ID comparison with a changed basis as idempotent; and
emitted different bytes when manifest-kind set order changed.

The corrected contract uses a shared, domain-separated, length-prefixed target
inventory digest in the producer and validator. The validator independently
recomputes it and enforces one exact target input. Complete reflective string
validation rejects invalid UTF-8 in producer objects before JSON encoding.
Native-behavior unknowns are counted by target input, local provenance, exact
ELF path, and permitted scope. Each supported undigested external input must
have one exact source-bound binding unknown, while external input metadata and
provenance versions must agree.

Coverage disagreement now validates the precise informational fact shape,
source-equivalent evidence and provenance, external comparison context, and
semantic subject. `AddComparison` is idempotent only for the same complete
tuple and basis; injected-digest tests force endpoint, type, and basis
collisions and observe fail-closed errors. Canonical encoding sorts documented
non-semantic nested sets on a copy, while preserving operation-argument,
data-flow-origin, and archive-entry sequence semantics.

These tests establish schema consistency properties, not truth of findings,
external source authenticity, plugin safety, or human approval. The remaining
interpretation and boundary judgment belongs to the independent reviewer.
