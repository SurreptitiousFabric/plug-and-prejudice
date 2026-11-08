# Severity model

Severity describes the potential consequence visible in the evidence and its
context. It does not describe certainty, intent, runtime reachability, or
whether a plugin is trustworthy. Those are separate dimensions.

## Levels

| Level | Meaning | Current examples |
|---|---|---|
| **Critical** | The visible operation directly targets catastrophic, broadly destructive impact without needing another unobserved step. Reserve this for exceptional cases. | Literal recursive deletion of filesystem root. |
| **High** | The operation can plausibly yield code execution from an uninspected source, another user's authority, credential or raw-storage disclosure, or severe home/system/storage destruction. | Network content piped to a shell; `sudo`/`pkexec`/`su`/`doas`; access to SSH/browser credentials or raw storage; raw-device writes; deletion of home, credential, persistence, or system targets. |
| **Medium** | The behavior can materially change future execution, obscure what runs, undermine the plugin contract, or leave consequential behavior unknown, but the visible evidence is not itself catastrophic. | Persistence setup; `eval`; recursive or dynamic deletion of an ordinary target; invalid manifest; native executable behavior that metadata cannot establish. |
| **Low** | The evidence shows a bounded potentially harmful side effect whose visible target is ordinary and non-sensitive. | Deleting one explicit temporary/cache path without recursive or dynamic arguments. |
| **Informational** | A contextual finding worth explaining that does not itself imply a meaningful adverse consequence. | Reserved for explanatory findings; ordinary commands and resource access are normally neutral `operations[]`/`resources[]` facts instead of warnings. |

## Separate dimensions

- **Claim** answers what kind of statement this is: directly established
  `fact`, reasoned `inference`, or explicit `unknown`.
- **Confidence** answers how certain the extraction or conclusion is. A
  high-impact possibility can have low confidence; a harmless fact can have
  high confidence.
- **Scope** answers apparent reachability: `runtime`, `repository-tooling`, or
  `unknown`. A high-severity command in test tooling remains high potential
  impact but is visibly separated from runtime-reachable behavior.
- **Provenance** answers which deterministic rule or later reasoning stage
  produced the statement.

For example, an ELF helper produces high-confidence informational metadata
facts plus a separate high-confidence `native-behavior` unknown: it is certain
which bounded metadata was observed, while runtime behavior remains unknown.
Privilege-related file metadata is a separate high-impact fact and still does
not prove the installer preserves it. Conversely, a constructed deletion path may retain
meaningful severity while confidence is reduced because the runtime target is
dynamic.

## Context rules

Command names do not determine severity by themselves. A rule must consider the
visible target, flags, data flow, sensitivity, persistence effect, dynamic
portions, and scope. `curl` alone is a neutral network operation; `curl | bash`
is High because network-provided bytes flow directly to an interpreter. `rm`
of an explicit cache file is Low; recursive removal of `/` is Critical.

Severity must not be reduced merely because a behavior is common for a plugin,
nor increased because a command looks frightening. Expectedness belongs in the
explanation and any inference about purpose. Failed authorization, nonexistent
paths, and runtime conditions remain unknown unless static evidence establishes
them.

## Change discipline

A new or changed severity rule must include:

1. a stated consequence and the context that triggers it;
2. positive, negative, and legitimate-use tests;
3. evidence and provenance assertions;
4. boundary tests around adjacent severity levels; and
5. an update to the deterministic rule catalogue.

Do not compute an overall safety score from these levels. Finding counts and
severity labels are inputs to a user's trust decision, not a verdict.

## Review summary rubric

The required report summary follows [ADR 0018](decisions/0018-independent-review-dimensions.md).
Security impact is the highest fact/inference severity. Evidence confidence is
the weakest confidence among those highest-impact reasons and is accompanied by
the complete node-confidence distribution. Coverage uses an explicit retained
artifact-file denominator, and unknown behavior has its own categorical rubric.
These fields remain separate and cannot be combined into a safety result.
