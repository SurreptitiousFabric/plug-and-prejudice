# Omarchy panel contract

Status: implemented prototype; visual and accessibility review still required.

The repository root is a schema-1 Omarchy `panel` plugin. It has no service or
bar-widget entry point. Omarchy injects the manifest and shell host; the panel
uses the manifest source directory only to locate its sibling trusted broker.

## Interaction

- Opening lists bounded third-party directory IDs without reading manifests.
- `j`/`k` or arrow keys move the single cursor; pointer hover updates the same
  cursor.
- `Enter` reviews the selected plugin.
- In a report, `h`/`l` or horizontal arrows switch between Findings, Resources,
  and Limitations; `j`/`k` moves through evidence rows.
- `Esc` returns one level and then closes the panel.
- Closing terminates any broker child; no scan continues invisibly.

The report deliberately has no approval action, safety badge, numeric score,
Markdown, links, dashboard, or LLM presentation. `complete` means only that the
implemented deterministic coverage completed. Empty findings always carry an
explicit non-safety statement.

## Hostile presentation data

The broker validates the report before stdout reaches QML. The panel then
defensively checks the outer shape, caps each visible collection at 500 rows,
caps every displayed string, replaces C0/C1 controls and Unicode bidi-control
characters, and renders only QML `Text` in its default plain-text mode. Evidence
paths are inert labels. Commands and excerpts wrap as inert monospace text and
are never clickable or copied implicitly.

Installed-plugin discovery returns IDs only. Plugin-authored names are read only
inside the sandbox and appear only after validation and normalization.

## Process boundary

The wrapper launches only `bin/plug-prejudice-broker` through a QML command
array. It never constructs a shell command. The selected ID is validated by the
UI and independently by the broker; only the broker resolves it to a target.
The scanner path is the broker's trusted sibling and must be a static ELF.

## Important limitation

The panel runs inside the long-lived `omarchy-shell` process alongside enabled
plugins. A malicious plugin that is already enabled may interfere with the
desktop session, panel, or displayed result. The standalone broker/CLI remains
the higher-assurance recovery interface when independently installed and
launched from the normal host session. That claim assumes the real host user
and mount namespaces; the broker does not authenticate an arbitrary caller's
namespaces. Reviewing before enablement is outside the initial release scope.

## Verification

`scripts/test-qml.sh` performs QML type checks and a real Quickshell component
load with hostile control/bidi text assertions without opening the panel or
launching a scan. `scripts/test-installed-integration.sh` is explicit and
opt-in; it builds static binaries and exercises panel discovery, broker,
Bubblewrap, scanner, validation, and report-model ingestion against one selected
installed plugin.
