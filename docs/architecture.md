# Architecture

## Approved initial scope

Version 1 reviews already-installed Omarchy Shell plugins. It does not enable,
disable, update, modify, or execute them. Support for reviewing before install
may be designed later without weakening the initial trust boundaries.

```text
Omarchy QML panel
    |
    | fixed arguments and structured status
    v
trusted local broker
    |
    | fixed Bubblewrap policy
    v
sandboxed Go scanner ----> versioned JSON report
    ^                               |
    | read-only /target             v
installed plugin              schema validator
                                    |
                                    v
                            plain-text presentation
```

The scanner is an independent CLI. The Omarchy component is only selection,
progress, and presentation. Deterministic analysis has no network access and no
LLM dependency.

## Components

### Omarchy wrapper

- Uses documented Omarchy plugin discovery and native visual conventions.
- Obtains a bounded list of valid installed directory IDs from the trusted
  broker without reading plugin-authored manifests merely to populate the UI.
  The broker reads fixed-size directory batches and fails visibly above 1,024
  valid plugins or 4,096 total root entries rather than allocating an
  attacker-sized directory listing or silently truncating it.
- Passes a plugin identity to the broker without invoking a shell interpreter.
- Consumes a versioned structured report rather than scraping terminal output.
- Treats every report string as hostile plain text.

### Broker

- Resolves an installed plugin identity to an approved canonical directory.
- Optionally pins one explicitly selected Omarchy audit JSON file and exposes
  only that descriptor read-only to the scanner; it never runs the audit.
- Opens and pins the selected directory before constructing containment; the
  scanner binds its report to the resulting bounded file inventory and root
  digest. Git metadata is hostile target data, not trusted provenance.
- Rejects a structurally valid scanner report unless its target identity
  exactly matches the selected plugin ID, its root digest is present, and its
  resource metadata exactly matches the compiled broker policy.
- Constructs a fixed Bubblewrap command from trusted constants.
- Creates a controlled output area and applies resource/time limits.
- Re-enters a randomized, verified systemd user scope before resolving the
  target, then applies process rlimits and constructs Bubblewrap containment.
- Fails closed if required isolation cannot be established.

### Deterministic scanner

- Runs as a single Go executable inside the sandbox.
- Reads only `/target` and writes only its controlled output.
- Does not execute target files or invoke language runtimes on them.
- Applies bounded inventory, parsing, data-flow, correlation, and reporting.

### Optional LLM stage

This is outside version 1. If added later, it must be a separate network-enabled
broker that can read only a minimized, redacted fact bundle approved for
disclosure. Its output is inference and must cite deterministic fact IDs.

## Report principles

Reports distinguish `fact`, `inference`, and `unknown`. Severity describes
potential contextual impact and is independent of confidence and provenance.
Every finding references inspectable evidence and records incomplete analysis.
