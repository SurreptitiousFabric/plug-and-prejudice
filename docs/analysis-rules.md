# Deterministic analysis rules

Status: evolving pre-release catalogue.

## Rule contract

Every deterministic rule must define:

- the observable fact it consumes;
- the context that changes consequence or severity;
- the evidence location and operation text it returns;
- cases it intentionally does not report;
- uncertainty and parser limitations; and
- positive, negative, benign, comment/string-lookalike, and malformed-input
  tests where applicable.

Commands are recorded neutrally in `operations[]`. A command name alone is not
a security finding. Findings correlate operations with context and reference
the operation IDs from which they were derived.

## Manifest contract

The scanner parses `manifest.json` strictly as data. It preserves declared
identity, version, description, kinds, and entry points as author claims, then
independently checks the current Omarchy schema-1 requirements implemented by
the official validator:

- schema version 1;
- non-empty, non-reserved, path-safe ID;
- required name and version;
- a non-empty kinds array;
- required entry-point key for each known kind;
- safe relative entry-point paths; and
- inspectable declared entry-point files.

Manifest errors are medium because they undermine identity and load-contract
analysis, not because malformed metadata itself compromises the host.

## Shell syntax

Shell files are selected by recognized extension or shell shebang and parsed
with `mvdan.cc/sh/v3/syntax` in Bash-compatible mode. The analyzer never uses
the interpreter package and never executes the syntax tree.

Current correlations:

- `curl` or `wget` piped directly into `sh`, `bash`, `zsh`, Python, or Node is
  high-severity download-and-execute.
- `sudo`, `pkexec`, `su`, or `doas` is a high-severity privilege-elevation fact;
  successful authorization remains unknown.
- `eval` is medium-severity dynamic execution because runtime text is reparsed
  as shell syntax.

An ordinary download is an operation, not a warning. Comments and quoted words
do not become commands. Dynamic word portions are represented as `<dynamic>`
and reduce confidence rather than being guessed.

## QML process extraction

QML must not be loaded into Qt for inspection. A bounded lexical extractor finds
`Process` blocks and their `command` properties outside comments and string
literals. Literal arrays become structured operations; expressions are marked
dynamic. This is intentionally not represented as a complete QML semantic
parser.

Inline `bash -c`-style programs are parsed with the shell AST before shell or
download-and-execute findings are emitted. A literal QML `curl` command alone
does not produce a warning.

## Repository metadata

Git object databases, reflogs, and standard `hooks/*.sample` files are not
plugin behavior and are excluded from semantic analysis. Real non-sample Git
hooks remain visible. Git database files remain in inventory but do not consume
source-content limits.

## Known gaps

- Operation reachability/scope does not yet distinguish runtime entry-point
  code from development and release tooling.
- Python, JavaScript outside QML, native binary headers/imports, filesystem
  paths, persistence, credential access, and domain extraction remain pending.
- QML property aliases and constructed command arrays can remain dynamic.
- The report schema is versioned but not yet declared stable.
