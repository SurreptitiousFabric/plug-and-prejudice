# Omarchy panel contract

Status: implemented prototype; first local visual review completed on the
current Omarchy theme at 1.5× and 2× display scaling. Independent human visual
and accessibility review is still required before release.

The repository root is a schema-1 Omarchy `panel` plugin. It has no service or
bar-widget entry point. Omarchy injects the manifest and shell host, but the
panel does not derive executable paths from the user-writable plugin checkout.

## Interaction

- Opening lists bounded third-party directory IDs without reading manifests.
- Enumeration is bounded in the broker before JSON allocation: more than 1,024
  valid plugins or 4,096 total root entries produces an explicit error rather
  than a partial list.
- `j`/`k` or arrow keys move the single cursor; pointer hover updates the same
  cursor.
- `Enter` reviews the selected plugin.
- In a report, `h`/`l` or horizontal arrows switch between Findings, Commands,
  Resources, and Limits; `j`/`k` moves through evidence rows.
- `Esc` returns one level and then closes the panel.
- Closing terminates any broker child; no scan continues invisibly.

The Commands section keeps neutral extracted operations visible without turning
them into warnings. Each row shows a bounded command/action name, bounded
arguments, dynamic-value status, scope, confidence, and inert source evidence.
Finding, command, and resource rows also show their stable `PP-` reference and
structured rule, analyzer version, and evidence-source provenance. Finding
details render at most 16 typed evidence-chain edges as inert plain text.
The panel's 500-row Findings budget is filled by severity (Critical through
Informational), and its 500-row Resources budget places sensitive resources
first. Original scanner order remains stable within each group. This display
prioritization does not change the canonical structured report, and omitted
row totals remain explicit.
The Limits section places scan errors labelled `ERROR` before analysis
limitations labelled `UNKNOWN`. It shares a 500-row display budget fairly when
both kinds are present, then reallocates unused capacity; source totals remain
visible so omission is explicit.
The report header labels the manifest description and up to eight declared
plugin kinds as an `AUTHOR CLAIM`. It does not infer purpose from behavior or
present author metadata as a scanner conclusion. Missing or unparseable
manifest metadata remains explicit.
The header presents security impact, evidence confidence, analysis coverage,
and unknown behavior as four separate labels. It also shows the exact
fully-analyzed/total artifact-unit denominator, fact/inference/unresolved
counts, and up to eight main reasons with stable references where available.
These are plain-text review dimensions, not a combined dashboard score.
The report deliberately has no approval action, safety badge, numeric score,
Markdown, links, dashboard, or LLM presentation. `complete` means only that the
implemented deterministic coverage completed. Empty findings always carry an
explicit non-safety statement.

## Hostile presentation data

The broker validates the report before stdout reaches QML, including an exact
binding between the selected plugin ID, report target identity, nonempty root
digest, and compiled resource policy. Broker errors are normalized as hostile
plain text and capped at 4 KiB before entering QML's stderr collector. The panel then
defensively checks the outer shape, caps each visible collection at 500 rows
(with one shared cap for errors and limitations), caps every displayed string,
replaces disallowed C0/C1 controls and Unicode bidi-control characters (the
complete Unicode `Bidi_Control` set), and flattens tab, newline, and carriage
return in single-line metadata such as names, titles, codes, paths, command
arguments, kinds, and author claims. Bounded explanation, evidence, and
diagnostic blocks may retain line breaks for readability. Every production QML
`Text` object explicitly uses
`Text.PlainText`. Qt's default `Text.AutoText` is forbidden because its rich-text
heuristic can interpret hostile markup and load remote images. Evidence
paths, public references, rule IDs, analyzer identities, versions, sources, and
edge labels are inert. Commands and excerpts wrap as inert monospace text and
are never clickable or copied implicitly.

Installed-plugin discovery returns IDs only. Plugin-authored names are read only
inside the sandbox and appear only after validation and normalization.

## Process boundary

The wrapper launches only fixed `/usr/bin/plug-prejudice-broker` through a QML
command array. It never constructs a shell command. A list response must carry
protocol version `1.0.0` and a nonempty reviewer build version before the UI
accepts it. The selected ID is validated by the UI and independently by the
broker; only the broker resolves it to a target. The broker launches only fixed
`/usr/bin/plug-prejudice`, requires its report version to match the broker build,
and requires a root-owned static ELF.

## Important limitation

The panel runs inside the long-lived `omarchy-shell` process alongside enabled
plugins. A malicious plugin that is already enabled may interfere with the
desktop session, panel, or displayed result. The standalone broker/CLI remains
the higher-assurance recovery interface. Reviewing before enablement is outside
the initial release scope.

## Verification

`scripts/test-qml.sh` performs QML type checks and a real Quickshell component
load with hostile control/bidi text, evidence-location, and bounded cursor
navigation assertions without opening the panel or launching a scan.
`tests/PanelVisualHarness.qml` renders a trusted synthetic incomplete report for
manual review without a broker path or target plugin. It is test support, not a
production entry point. `scripts/test-installed-integration.sh` is explicit and
opt-in; it builds static binaries and exercises panel discovery, broker,
Bubblewrap, scanner, validation, and report-model ingestion against one selected
installed plugin.

The first visual pass found that nested evidence represented through a QML model
was incorrectly rejected by an `Array.isArray` check. The corrected view shows
the inert command excerpt and exact file/line location beneath each finding.
The incomplete-scan warning, fact/inference labels, selected tab, scrollable
rows, and narrow-window wrapping were also inspected. This is evidence for the
tested theme and sizes only; it is not a general accessibility certification.
