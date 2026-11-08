# 0017: Optional pinned Omarchy audit evidence

- Status: implemented in development tree; independent boundary/schema review pending
- Date: 2026-08-28

## Context

Omarchy PR #8439 proposes a useful first-party capability audit, but remains
open and emits unversioned JSON. Plug & Prejudice must not execute that audit,
depend on it for standalone scanning, silently follow a changing schema, or
treat first-party output as independent proof of safety.

## Decision

Accept an explicitly selected local JSON file only when the caller also names
the pinned `pr8439-732b104` format. The broker pins a non-symlink regular-file
descriptor and mounts only that file read-only at `/audit/omarchy.json` inside
the existing networkless scanner sandbox. The scanner reads at most 1 MiB,
checks identity/size/timestamp stability, rejects unknown JSON members and
trailing values, and enforces nested collection, encoded-string, duplicate,
enum, and summary-consistency limits.

The adapter imports commands, network hosts, file reads/writes, and upstream
risks with `omarchy-audit` evidence-source provenance. Exact comparable
observations receive typed `corroborates` edges. Set differences receive
informational coverage-disagreement facts and typed `disagrees-with` edges;
they never assert that either analyzer is wrong. Upstream verdicts are parsed
for contract validation but are not adopted as Plug & Prejudice conclusions.

The current upstream format includes a plugin ID but no content digest. The
adapter therefore requires manifest-ID equality and always emits an explicit
snapshot-binding unknown: agreement does not establish that both scans saw the
same bytes. A future upstream version with a digest needs a new pinned adapter;
it must not weaken this one in place.

No audit is generated or executed by Plug & Prejudice. Omitting both optional
flags preserves standalone analysis behavior and requires no Omarchy
installation.

## Residual risk and review gate

The external analyzer may be stale, buggy, run against different bytes, or use
different runtime/tooling scope. Its `pluginDir` is parsed as a hostile label
and never opened. Exact equality can report benign differences caused by
normalization.

Independent human review is required for descriptor propagation through
systemd and Bubblewrap, strict schema fidelity to the pinned upstream commit,
target binding, comparison keys, relationship semantics, hostile strings,
limits, and UI wording before merge.
