# Release readiness

Status: pre-release evidence checklist. A passing row is necessary but not
sufficient for release. No automated result proves that the reviewer or a
reviewed plugin is safe.

Retained development observations are stored under
[`docs/release-evidence`](release-evidence/). They identify their source state
and limitations and must not be mistaken for final signed release provenance.

## State meanings

- **Implemented**: source and focused tests exist in the current development
  tree; the change may still require human review and merge.
- **Verified locally**: the stated command or observation has succeeded on the
  current ARM64 Arch/Omarchy development system.
- **Human gate**: a person must inspect the change or behavior before merge or
  release.
- **Decision pending**: an owner-approved architecture decision is required
  before implementation.
- **Missing**: required release evidence or implementation does not yet exist.

## Product and trust boundaries

| Requirement | Required evidence | Current state |
|---|---|---|
| Target code is never executed | Code review of every target-data path; tests use fixtures only as bytes; architecture regression test rejects process/plugin execution APIs in target-consuming production packages | Implemented and mechanically guarded; human security review remains required because the guard is not a proof |
| Scanner is independent of Omarchy | Standalone Go CLI accepts an explicit target and emits versioned JSON | Implemented |
| Wrapper remains thin | QML selects IDs, invokes one fixed broker command array, and renders validated JSON through explicit `Text.PlainText` primitives | Implemented with a structural plain-text regression guard; report-rendering review required |
| Rejected scanner output cannot amplify broker diagnostics into QML | Shared control/bidi normalization and 4 KiB pre-collector broker stderr cap with hostile-field tests | Implemented and tested |
| Deterministic scan has no network | Bubblewrap uses a private network namespace and exposes no network utility/runtime; an architecture regression test rejects common network APIs in scanner-side production packages and allowlists only MIME sniffing from `net/http` | Implemented and mechanically guarded; sandbox changes await human review |
| Filesystem access is least privilege | Only the pinned target is read-only; private `/tmp`; no home, credentials, session sockets, or host process view | Verified locally; sandbox changes await human review |
| CPU, memory, process, file-descriptor, output, and wall limits fail closed | Adversarial systemd-scope, rlimit, Bubblewrap, timeout, both-stream output-bound, and prompt-cancellation tests | Implemented and verified locally; ADR 0003 review pending |
| Trusted containment tools are immutable to plugins | Fixed root-owned, non-symlink, non-group/world-writable systemd-run and Bubblewrap paths | Implemented and verified locally; human sandbox review required |
| Trusted reviewer executables are immutable to plugins | Root-owned fixed broker/scanner paths with version handshake and no fallback | Implemented with fixed `/usr/bin` paths, protocol/build handshake, and package template; ADR 0004, package ownership evidence, and human review remain pending |
| Higher-assurance launch precondition is preserved | Independently installed CLI launched from the normal host session; no claim for attacker-created caller namespaces | Documented across README, architecture, threat, sandbox, and release procedures; human deployment review remains required |
| LLM is unnecessary and no data leaves the host | No LLM client or external disclosure path in version 1 | Implemented by absence; keep under review |

## Analysis and reports

| Requirement | Required evidence | Current state |
|---|---|---|
| Facts, inferences, and unknowns remain distinct | Schema enums, validation, UI labels, and tests | Implemented |
| Findings carry evidence and provenance | Validator rejects missing/invalid relationships and oversized object graphs; scenario and renderer tests | Implemented |
| Identical inspected input produces stable analysis collections and IDs | Randomized source-map and inventory permutations serialize to identical analysis bytes; scan timestamps remain explicitly variable metadata | Implemented and tested across manifest, source, resource, finding, limitation, and relationship output |
| Report is bound to the user's selected plugin | Broker requires exact selected ID, canonical nonempty inventory root digest, and exact compiled resource metadata before stdout | Implemented and tested |
| QML parses exactly the semantic report object accepted by the broker | Approved bounded re-encoding of the validated typed report with parser-differential and no-partial-output tests | Implemented and tested; ADR 0007 and independent report/QML review remain pending |
| Context limits false positives | Parsed shell AST, bounded QML extraction, neutral resource facts, benign/legitimate fixtures | Implemented for documented rules; coverage remains incomplete |
| Required behavior scenarios remain testable without execution | Inert fixtures cover harmless behavior, network access, filesystem writes, credentials, privilege elevation, deletion, persistence, download-and-execute, dynamic/obfuscated shell, suspicious subprocesses, legitimate dangerous-command context, and combined hostile behavior | Implemented; a global fixture guard rejects symlinks, special files, executable bits, and files above 64 KiB before tests consume regular-file bytes only |
| Unsupported semantics become limitations | Language, QML imperative-command, malformed shell/ELF, native binary, and resource-limit coverage | Implemented |
| Hostile filesystem input is bounded | Incremental capped directory reads; file count/depth/source/binary budgets; symlink, hard-link, and special-file handling; inode checks | Implemented and tested |
| Selected target remains beneath installed-plugin root | Approved descriptor-relative `openat2` selection and parent-swap race tests | Implemented and tested on native ARM64; ADR 0006 and independent path-traversal review remain pending |
| Nested mounts cannot disclose unrelated files | Approved opened-descriptor mount-ID policy and real same-filesystem bind-mount test | Implemented with automatic test skip when unprivileged bind mounts are forbidden; native AMD64 and independent containment review remain pending |
| Hostile source cannot crash structural analysis | Curated malformed seeds plus repeatable Go fuzz targets | Implemented; longer fuzz campaigns still desirable |
| Scanner result amplification is bounded before serialization | Approved inventory/analysis count, nested manifest/ELF/relationship caps, encoded-string and aggregate producer budgets, plus incomplete-report tests | Implemented with exact JSON-encoded 3 MiB inventory and 6 MiB analysis budgets, nested producer/validator caps, atomic final encoding, and hostile boundary tests; ADR 0005 and independent semantics review remain pending |
| Report schema is release stable | Version policy, compatibility rules, fixtures, and migration policy approved | Implemented; compatibility contract requires human approval |
| Python/JavaScript semantic parsing | Approved dependency boundary and hostile-input evaluation | Implemented with selective pure-Go grammar subsets, timeout/production caps, fuzz seeds, and trusted syntax oracles; ADR 0002 and independent dependency/parser review remain pending |
| QML literal assignment flow | Unique bounded root-property strings/arrays, multi-hop origins, duplicate/cycle/shadow rejection, definition/depth caps, and no evaluation | Implemented under ADR 0019 with direct, chained, ambiguous, cyclic, nested, budget, hostile, race, and fuzz coverage; independent lexical/rule review pending |
| Multi-step behavior correlations | Exact-path and co-capability rules with traceable operation IDs, explicit missing-flow language, versioned provenance, deterministic bounds, false-positive tests, and documented severity/confidence | Download/executable/invocation, sensitive-read/network, exact startup-path execution, dynamic/privilege, systemd activation, and exact one-source desktop/systemd transfer-to-configured-command relationships implemented and locally verified; independent ADR 0008 rule-semantics review remains pending |
| Desktop/systemd artifact relationships | Bounded inert parsers, direct configuration facts, explicit unknowns, enablement/activation-to-execution chains, hostile tests, and no target execution | Desktop/autostart ADR 0011 and systemd ADR 0012 implemented and locally verified; independent parser/rule review and indirect-script coverage remain pending |
| Hyprland configuration review | Bounded inert directive parser, embedded non-executing shell AST, lifecycle/source/native-plugin distinctions, evidence remapping, unknowns, and hostile tests | ADR 0013 implemented and locally verified; independent parser/rule review remains pending |
| Indirect script/config reachability | Exact retained-path joins, ambiguity unknowns, caller/callee evidence chains, bounded multi-hop scope propagation, and no filesystem following | ADR 0014 implemented and locally verified; independent path/correlation review and dynamic/import/archive-member reachability remain pending |
| Archive/bundled payload inventory | ZIP/TAR bounded metadata, compressed-format identification, traversal/link facts, payload unknowns, nested schema/producer caps, and zero extraction | ADR 0015 implemented and locally verified; independent parser/allocation/path review and nested payload semantics remain pending |
| Stable evidence chains | Public references stable under unrelated insertion, structured rule/analyzer/source provenance, claim-typed edges, cross-source corroboration semantics, strict migration, and hostile plain-text rendering | Schema 2 graph, validator, golden report, migration rejection, producer edge budget, and QML presentation implemented; independent ADR 0009 schema/validator/rendering review remains pending |
| Optional Omarchy audit evidence | Pinned/versioned strict adapter, descriptor-only read-only mount, source provenance, agreement/disagreement semantics, malformed/oversized/path tests, and unchanged standalone mode | PR #8439 revision `732b104` adapter implemented under ADR 0017; upstream lacks content digest so imports remain explicitly snapshot-unbound; independent boundary/schema review pending |

## Omarchy experience

| Requirement | Required evidence | Current state |
|---|---|---|
| Manifest matches current official schema | `omarchy plugin validate .` on the release tree | Verified locally; rerun for release candidate |
| Native interaction and appearance | Human review on supported Omarchy theme/scale combinations, keyboard and pointer | First local visual pass complete; independent human review missing |
| Accessibility semantics | Keyboard paths, Qt accessibility roles/names/actions, AT-SPI inspection | Semantics implemented; independent AT-SPI/human review missing |
| Installed end-to-end review | Explicit integration test against a selected installed plugin through broker and sandbox | Test exists; rerun after packaging boundary and with explicit desktop authorization |
| Review does not imply approval | No safe badge/score; incomplete/empty reports state limitations and non-safety | Implemented |
| Independent review dimensions | Validator-recomputed impact/confidence/coverage/unknown rubric, explicit testable denominator, stable main-reason references, counts, hostile QML and accessibility semantics | Implemented under ADR 0018; independent rubric/schema/UX/accessibility review pending |
| Stated purpose remains attributable | Header shows bounded manifest description and declared kinds under an explicit `AUTHOR CLAIM` label; layout whitespace and bidi controls cannot create apparent header rows | Implemented and structurally/hostile-input tested; independent UX review required |
| Neutral commands remain inspectable | Bounded Commands section shows operation category, command/action, arguments, dynamic state, scope, confidence, and source evidence without promoting operations to warnings | Implemented; independent UX and hostile-rendering review required |
| Scan failures remain visible | Limits section presents `ERROR` rows before `UNKNOWN` analysis limitations under a fair shared bound; hostile text remains inert and omitted rows are disclosed | Implemented and headlessly tested; independent UX review required |

## Build, supply chain, and release

| Requirement | Required evidence | Current state |
|---|---|---|
| Go quality gates | `go test ./...`, `go test -race ./...`, `go vet ./...`, `go mod verify` | Verified locally |
| Vulnerability scan | Pinned `govulncheck` version, documented database/tool scope, and retained release result | `scripts/verify-vulnerabilities.sh` passes locally with v1.7.0; rerun and retain output for release candidate |
| QML quality gates | Static type/lint checks and component-model tests | Implemented; do not run live-shell checks without user authorization |
| Native ARM64 package | Clean package build, tests, ELF static-PIE assertions, Pacman file ownership | Development-tree native package passed `makepkg`, package tests, and exact offline inventory/mode/static-ELF verification; final clean signed-tag package and actual Pacman installation/ownership evidence remain missing |
| Native x86-64 package | Same evidence on native x86-64, not cross-compilation alone | Missing |
| CI is least privilege and reproducible | Human-reviewed pinned actions, read-only permissions, safe triggers, no secrets or hidden failures, per-job timeouts, native architecture, byte-reproducibility checks, and structured live-test pass/skip artifacts on both architectures | CI and tag-only release workflows use commit-pinned actions; release write/OIDC/attestation grants are confined to the publish job and mechanically policy-checked; live containment summaries distinguish pass, fail, skip, and did-not-build, while native systemd/Bubblewrap evidence remains a separate human/platform gate |
| Dependency graph and notices are auditable | Production linkage inventory, graph-only test dependencies, license obligations, and release review procedure | Production inventory and notices are enforced; release-only CycloneDX v1.10.0 AMD64/ARM64 tool artifacts are SHA-256 pinned; one module plus four binary-specific SBOMs and their checksum binding are exercised; final clean-builder/SBOM human review remains required |
| Release identity is verifiable | Final version injection, signed tag/checksums/provenance, SBOM, documented verification | Version-bound native binaries, CycloneDX generation, checksum manifest, GitHub artifact attestation, tag publication, and consumer verification procedure implemented; first approved signed tag/run and retained evidence missing |
| Public installation/update/removal works | Tested instructions using official Omarchy and Arch mechanisms; no hooks or self-install | ARM64 development packages passed isolated, networkless Pacman install/ownership/upgrade/handshake/removal; normal-policy disposable ARM64/x86-64 final-candidate runs and public package channel remain missing |
| Security response is ready | Public security policy and private advisory path | Verified on the public repository: the policy is discoverable, private vulnerability reporting is enabled, and Dependabot security updates, secret scanning, and push protection are enabled; the intake workflow still requires a release-owner exercise |
| Contributor intake preserves project boundaries | Public bug and detection-rule forms, private-vulnerability routing, and a security-aware pull-request checklist | Implemented and syntax-checked; first rendered GitHub form and maintainer-workflow review remain required |

## Required human approvals

The evidence format, review questions, commands, and sign-off requirements are
defined in [`human-review-guide.md`](human-review-guide.md). Approval must be
commit-bound and track-specific.

Before a release candidate can be tagged:

1. Review and approve ADR 0003 and its resource-containment implementation.
2. Decide ADR 0004, then review the executable/package trust-boundary change.
3. Decide ADR 0005 and review result-production budgets and incomplete-report semantics.
4. Decide ADR 0006 and review selected-tree and nested-mount containment.
5. Decide ADR 0007 and review canonical broker serialization plus QML ingestion.
6. Review report validation and QML rendering as hostile-data boundaries.
7. Perform independent Omarchy UX and accessibility review.
8. Review pinned CI/release workflows and their permissions.
9. Review the final dependency graph, SBOM, package contents, checksums, and
   release provenance.

Release remains blocked while any required row is **Decision pending**,
**Missing**, or lacks its stated human gate. Do not convert this checklist into
an unexplained numeric score.
