# 0008: Evidence-backed behavior correlation engine

- Status: implemented in development tree; independent rule-semantics review pending
- Date: 2026-08-28

## Context

Individual command, path, and domain capabilities are necessary evidence but
do not explain why combinations matter. At the same time, source-level
co-presence is not proof of control flow or data flow. A correlation engine must
make useful relationships visible without turning an unsupported suspicion into
a fact or introducing an unbounded cross product over hostile input.

## Decision

Add a deterministic correlation stage that consumes only the bounded retained
operations and resources. It does not reparse source, inspect the host, execute
target content, or use a network or LLM path.

Version-one rules distinguish two evidence strengths:

- exact ordered literal-path relationships, such as download to a path,
  executable permission change, and later invocation of that path, or a write
  to a known startup path followed by invocation of that same path;
- exact one-source `cp`/`install`/`mv` transfers of an inspected desktop or
  systemd artifact to an exact startup-related file destination, joined to the
  commands parsed from that precise source artifact; and
- capability co-presence, such as sensitive-file read plus outbound network, or
  dynamic execution plus privilege elevation, where data flow is explicitly
  stated as unestablished.

Every output is an `inference`, cites every operation used by that inference,
retains bounded inert source evidence, and records versioned deterministic
provenance. Exact path relationships receive medium confidence. Co-presence
without a shared operation receives medium or low confidence depending on the
rule and dynamic values. Direct syntax-local pipelines remain facts produced by
the shell AST stage, not correlations.

The stage uses linear passes and indexed exact-path lookups over producer-bounded
collections. It does not form an all-pairs cross product. Existing finding,
evidence, relationship, hostile-string, and aggregate result budgets apply
before append; crossing them remains explicit and incomplete under ADR 0005.

## Deliberate exclusions

- Similar-looking path substrings are not relationships.
- Dynamic paths are not normalized or matched as literals.
- Operations in different files are not presented as ordered control flow.
- File reads plus network access do not claim exfiltration or successful access.
- Persistence plus an unrelated process launch is not correlated.
- A permission change that does not visibly add an execute bit is not called an
  executable transition.
- Missing data flow is not filled in by an LLM or heuristic keyword search.

## Verification and review gate

Tests cover positive, negative, legitimate, ambiguous, malformed, dynamic,
deduplication, provenance, relationship integrity, stable ordering, exact-path,
and executable-mode boundaries. Normal, race, fuzz, deterministic, producer
budget, validator, and hostile-presentation gates remain required.

An independent reviewer must approve rule semantics, severity/confidence
choices, false-positive posture, and explanations before merge. That human gate
cannot be satisfied by the automated tests.
