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

Operations and findings carry one of three conservative scope labels:

- `runtime`: declared QML entry-point code or a path reached through bounded
  textual references from runtime code;
- `repository-tooling`: conventional tests, examples, documentation, CI,
  validation, build, package, and release tooling; or
- `unknown`: reachability has not been established either way.

Reachability propagates only through already-inspected text. A referenced binary
can become runtime-scoped, but its bytes are never interpreted as source. Scope
describes apparent reachability, not whether an operation will actually run.

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

## Native ELF files

ELF files use a separate bounded byte budget. The scanner hashes the exact file
and parses class, byte order, architecture, ELF type, interpreter, imported
libraries, and symbol-table presence with Go's non-executing `debug/elf` reader.
Binary bytes never enter the source analyzer map.

Every ELF produces an `unknown` finding and an explicit
`native-binary-behavior` limitation. Metadata does not establish executable
behavior or prove that a binary corresponds to available source. Scope is
derived separately from textual runtime reachability.

## Known gaps

- Python, JavaScript outside QML, filesystem paths, persistence, credential
  access, and domain extraction remain pending.
- QML property aliases and constructed command arrays can remain dynamic.
- The report schema is versioned but not yet declared stable.
