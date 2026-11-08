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

Each inspected shell or QML source builds one bounded line-start index for
evidence locations and excerpts. Evidence lookup does not split or recount the
entire file for every operation; this prevents command-dense input from turning
line attribution into quadratic CPU work. Result cardinality and retained
string amplification remain a separate pending policy in ADR 0005.

`resources[]` records accessed domains, filesystem paths, persistence
mechanisms, access modes, sensitivity, confidence, scope, and the originating
operation without turning every capability into a warning.

Operations and findings carry one of three conservative scope labels:

- `runtime`: declared QML entry-point code or a path reached through bounded
  textual references from runtime code;
- `repository-tooling`: conventional tests, examples, documentation, CI,
  validation, build, package, and release tooling; or
- `unknown`: reachability has not been established either way.

Reachability propagates only through already-inspected text. A referenced binary
can become runtime-scoped, but its bytes are never interpreted as source. Scope
describes apparent reachability, not whether an operation will actually run.
Declared and propagated runtime reachability takes precedence over conventional
tooling directory/file names; an entry point under `tests/` is still runtime.
Undeclared entry-point keys do not create runtime reachability. Tooling basename
classification uses delimiter-separated words rather than arbitrary substrings.

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
- safe relative paths for every entry-point key, matching the shell registry's
  whole-object rejection behavior;
- newline-free, inspectable files for every declared entry-point key; and
- `barWidget.defaultSection` values of `left`, `center`, or `right` when present.

The inventory also reports any symbolic link outside `.git` as a medium
contract finding, matching the official CLI validator. Link targets are inert
evidence strings and are never followed.

Manifest errors are medium because they undermine identity and load-contract
analysis, not because malformed metadata itself compromises the host.

## Shell syntax

Shell files are selected by recognized extension or a shebang whose actual
interpreter basename is `sh`, `bash`, or `zsh` (including `env` forms), then
parsed with `mvdan.cc/sh/v3/syntax` in Bash-compatible mode. Names merely
containing `sh`, such as Fish or a `shim`, are not treated as Bash-compatible.
Fish receives an explicit unsupported-language limitation. The analyzer never
uses the interpreter package and never executes the syntax tree.

Current correlations:

- `curl` or `wget` piped as the adjacent parsed producer directly into `sh`,
  `bash`, `zsh`, Python, or Node is high-severity download-and-execute. A
  multi-stage pipeline is not collapsed across intervening transformations.
- `sudo`, `pkexec`, `su`, or `doas` is a high-severity privilege-elevation fact;
  successful authorization remains unknown.
- A direct literal command passed as the first argument to `sudo`, `pkexec`, or
  `doas`, or through recognized literal `command` and `env` forms, is recorded
  as a separate evidence-linked operation. This prevents nested capabilities
  such as credential access, persistence, network access, or deletion from
  being hidden by wrappers. Expansion is capped at four derived operations per
  parsed command. `command -v/-V` and `env` without a command are recognized as
  non-executing; supported `env` environment, unset, chdir, and argv0 options
  are skipped according to their operand roles. Unknown options, split-string
  forms, dynamic targets, and deeper nesting produce explicit limitations
  rather than guessed commands. `su` is not expanded because its command forms
  have different semantics.
- `eval` is medium-severity dynamic execution because runtime text is reparsed
  as shell syntax.
- `base64 --decode`, `xxd --revert`, or stdout-decoding OpenSSL forms
  piped directly into an interpreter is a medium fact: decoded bytes become
  runtime code and the visible source is harder to audit. Decoder use alone is
  neutral. A file containing both a recognized decoder and `eval` receives one
  medium-confidence inference, with both operations cited and an explicit
  statement that data flow between them was not established. A producer whose
  stdout is redirected away from the pipe is not called direct execution;
- network-capable commands expose syntactically explicit HTTP(S), FTP, SSH,
  Git, rsync, SCP-style, netcat host/port, and socat network endpoints as neutral
  resources. Extraction is command-position aware so local paths, Git ref
  syntax, and option values do not become domains; a constructed endpoint
  remains the explicit value `<dynamic>`;
- explicit curl/wget output options expose literal or dynamic filesystem writes.
  A later same-source invocation of the exact cleaned literal path produces a
  high, medium-confidence download-and-execute inference citing both operations;
  an intervening literal `chmod` that visibly adds an executable bit to the
  same path is included as a third step and cited operation;
  the explanation states that control flow, download success, permissions, and
  runtime bytes remain unestablished. Remote-derived or dynamic filenames are
  never correlated;
- a sensitive credential, authentication, browser, or session path read plus
  outbound network capability produces a high co-capability inference. It does
  not claim successful access, exfiltration, control flow, or data flow;
- a write to a recognized literal startup path followed later in the same
  source by invocation of that exact path produces a medium persistence-and-
  execution inference. Unrelated, reversed, cross-file, and dynamic paths are
  not correlated;
- a privilege-elevation operation with a dynamic command or argument produces
  a high, medium-confidence inference and retains the unresolved-wrapper
  limitation. Separate dynamic-execution and privilege operations produce only
  a low-confidence co-presence inference that explicitly denies established
  data or control flow;
- parsed filesystem commands expose read, write, copy/install, move, and delete
  targets using command-specific operand roles, including ordinary relative
  names that contain no slash. Reviewed common Coreutils flags, option values,
  short clusters, attached values, and `--` are distinguished from paths.
  Reference-file options expose the reference as a read and the targets as
  writes. Target-directory copy/install/move forms expose source roles plus the
  explicit directory without inventing final child paths; `install -d` exposes
  directory writes only. Conflicting, malformed, or unknown option forms
  produce a `filesystem-operand-resolution` limitation rather than guessed
  access;
- validated `dd` `if=FILE` and `of=FILE` assignments expose neutral input/output
  resources. The entire operand list must use recognized nonempty assignments;
  duplicate paths, dynamic operand names, malformed values, or unsupported
  assignments produce a `dd-operand-resolution` limitation with no partial path
  facts. Literal raw-storage inputs are high sensitive-storage facts and raw
  storage outputs are high destructive facts. Anchored Linux disk, partition,
  mapper, disk-alias, MD, device-mapper, and loop paths are covered; pseudo
  devices such as `/dev/null`, `/dev/zero`, and standard streams are not called
  raw storage;
- raw-storage classification is shared across recognized filesystem commands,
  downloader outputs, and shell redirections. Data reads are high
  sensitive-storage facts; data writes and destructive move/delete targets are
  high destructive facts. Metadata-only `readlink`, `touch`, `mkdir`, `chmod`,
  `chown`, and link operations remain neutral sensitive device resources rather
  than being mislabeled as disk-content modification;
- `ln` exposes only its explicit destination as a write; the scanner does not
  claim that symlink target text was read, and declines target-directory option
  forms whose operand roles are ambiguous to this bounded command model;
- parsed file-backed shell redirections expose read, write, append-as-write,
  and read-write targets as explicit `filesystem-redirection` operations.
  Redirection-only statements are covered; descriptor duplication, here-docs,
  and quoted lookalikes are not treated as file access;
- credential-related path components and exact store filenames produce high
  findings while preserving the attempted access mode. Coverage includes SSH,
  GnuPG, cloud CLIs, browser profiles, Docker/Kubernetes registries and clusters,
  Git/HTTP package credentials, desktop keyrings, password managers, and KeePass
  databases; broad substrings such as `keyring-design` are intentionally not
  treated as credential stores;
- `systemctl` `enable`/`reenable` verbs, mutating crontab invocations, and
  writes to exact shell/Fish/XDG autostart, systemd-user, cron, environment,
  Hyprland startup, or SSH authorized-key paths produce medium persistence
  findings; read-only `crontab -l` (including `-u USER`) and a unit merely named
  `enable` do not;
- deletion ranges from low for an explicit ordinary target through medium for
  recursive/dynamic paths, high for credential/home/system targets, and critical
  only for literal filesystem-root deletion. Known destructive commands treat
  ordinary relative operands as paths and honor `--`; recursion requires `-r`,
  `-R`, a short-option cluster containing either, or `--recursive`, not an
  arbitrary long option containing the letter `r`.

An ordinary download is an operation, not a warning. Comments and quoted words
do not become commands. Dynamic word portions are represented as `<dynamic>`
and reduce confidence rather than being guessed.

If a command name is also declared as a shell function earlier in the same
file, that invocation is retained as a medium-confidence
`shell-function-invocation`, external-program capability rules are suppressed,
and a coverage limitation is emitted. Calls textually before the declaration
retain ordinary command treatment. Function bodies are still parsed as source.
This is a conservative textual model; conditional definition control flow and
functions imported from other files remain unresolved.

## QML process extraction

QML must not be loaded into Qt for inspection. A bounded lexical extractor finds
`Process` blocks and only their top-level `command` properties outside comments,
single/double-quoted strings, and backtick template text. Nested object/JavaScript
`command` properties are not attributed to the enclosing Process. Literal arrays
become structured operations; expressions are marked dynamic and receive a
dedicated unknown linked to the operation and its `Process.command` use site.
This is intentionally not represented as a complete QML semantic parser.

Imperative JavaScript assignments such as `process.command = value` are
recognized only as a coverage boundary outside comments and strings. They force
an explicit incomplete limitation and a dedicated unknown citing the property
assignment location; the scanner does not guess the executable or arguments.

Unique root-object `property var` and `property string` definitions can supply
literal strings or arrays to `Process.command`. Plain-identifier references are
followed for at most 16 hops through at most 1,024 definitions. A successful
flow produces an informational fact citing assignments and use site. Duplicate
names, cycles, nested/shadowed properties, unsupported types, expressions, and
over-budget definitions remain dynamic/unknown; they are never evaluated. See
[ADR 0019](decisions/0019-bounded-qml-literal-flow.md).

Inline `bash -c`/`-lc` programs are parsed with the shell AST before shell or
download-and-execute findings are emitted. Download-to-interpreter correlation
requires adjacent pipeline commands and does not cross an intervening
transformation. Python `-c` and Node `-e`/`--eval` are recorded as inline dynamic
language execution but are never parsed as shell; their internal behavior
remains unknown and produces an explicit scoped
`inline-dynamic-language-analysis-unavailable` limitation. A literal QML
`curl` command alone does not produce a warning.

## Repository metadata

Git object databases, reflogs, and standard `hooks/*.sample` files are not
plugin behavior and are excluded from semantic analysis. Real non-sample Git
hooks remain visible. Git database files remain in inventory but do not consume
source-content limits.

## Desktop entries and autostart

`.desktop` files are parsed as inert bounded key-file text. Only an exact
`[Desktop Entry]` section and exact `Exec` key produce a configured process
operation. Comments, localized keys, and other sections are negative cases.
The tokenizer handles bounded whitespace, double quotes, backslash escaping,
and literal `%%`; runtime field codes make the operation dynamic and produce a
dedicated unknown. Duplicate `Exec` keys, malformed quoting, an absent command,
or line-budget exhaustion produce unknowns/limitations without selecting a
winner or guessing an executable.

A non-hidden entry under an exact target-relative `autostart` path component
produces a medium persistence fact. It does not establish installation,
enablement, or launch. Literal configured commands participate in the shared
command-capability rules. See
[ADR 0011](decisions/0011-desktop-entry-analysis.md).

A literal `cp`, `install`, or `mv` operation with exactly one visible source
can join to an exact retained `.desktop` artifact and an exact autostart-file
destination. The medium inference cites both the transfer and that artifact's
configured execution operations. Multiple sources, directory-only
destinations, ambiguous root/caller-relative source resolution, extension
mismatches, and artifacts without a parsed command do not correlate. Ambiguous
resolution becomes an explicit unknown. The relationship does not establish
control flow, transfer success, installation, enablement, launch, or command
success.

## Systemd units, services, and activation

Recognized systemd unit files and service/socket/timer/path drop-ins are parsed
as bounded inert text. Reviewed `Exec*` directives produce configured execution
operations; literal commands reuse shared capability rules. Environment
expansion and systemd specifiers produce linked unknowns, while literal `%%`
and the `:` no-environment-expansion prefix are negative cases. Privilege-
relaxing `+`/`!` prefixes are high direct facts whose authority remains
manager-dependent.

Install targets are informational facts, not proof of enablement. A same-file
combination of install metadata and execution produces a medium persistence
inference citing both operation types. Timer, path, and socket triggers are
informational facts. Exact safe `Unit=` references—or the documented default
same-basename service—can correlate to an inspected same-directory service and
produce a medium triggered-execution inference. Dynamic, unsafe, or missing
targets do not correlate.

The same exact one-source transfer rule can connect a retained systemd unit to
an exact persistent unit-file destination and its parsed `Exec*` commands.
Compatible unit extensions are required. This describes visible configuration
data flow only; it does not establish that a manager installs, loads, enables,
activates, or runs the unit.

Inline shell adjacent pipelines are parsed with the shell AST. Other inline
language programs remain explicit unknowns. Invalid UTF-8/NUL content,
unfinished continuations, malformed quoting, oversized tokens, and line/result
budgets fail without guessing. See
[ADR 0012](decisions/0012-systemd-unit-analysis.md).

## Hyprland configuration

Recognized Hyprland `.conf` paths are parsed as bounded inert UTF-8 text.
`exec`, `exec-once`, `exec-shutdown`, and exact `bind*` directives with an
`exec` dispatcher retain a configuration fact and feed their program text into
the non-executing shell AST. Nested commands, dynamic origins, capabilities,
and adjacent pipelines retain original configuration-line evidence. Optional
leading execution rules are stripped only with a visible closing bracket.

Startup/shutdown directives are medium lifecycle-persistence facts; ordinary
reload/key-bound commands remain neutral unless nested behavior supports a
separate rule. `source` is an include-reference fact and dynamic paths remain
unknown. `plugin` is a medium native-code-loading fact and never claims native
behavior or provenance. Comments, non-exec dispatchers, unrelated `.conf`
files, malformed rules/shell, invalid UTF-8/NUL, line exhaustion, and retained-
evidence limits have explicit negative or unknown paths. See
[ADR 0013](decisions/0013-hyprland-configuration-analysis.md).

## Indirect script and configuration reachability

Literal process/interpreter operands and static Hyprland `source` directives
are matched only against exact inventory-retained target-relative paths. A
single match produces a neutral execute-path resource; inspected callee
operations produce an informational inference citing caller and callee IDs.
Absolute, dynamic, missing, escaping, and self targets do not create edges.
Distinct root-relative and caller-directory-relative matches produce a
dedicated unknown instead of choosing one.

Runtime scope follows the same bounded graph across multiple hops. QML textual
references are limited to exact static quoted paths outside comments/template
literals; basename substrings no longer imply reachability. Working directory,
control flow, mode, interpreter behavior, and success remain explicitly
unestablished. See
[ADR 0014](decisions/0014-indirect-script-reachability.md).

## Archives and bundled payloads

ZIP/TAR containers receive bounded header/central-directory inventory without
opening member bodies or creating paths. Gzip, XZ, Zstandard, and bzip2 are
identified without decompression and therefore retain no member list. At most
4,096 ZIP/TAR entries retain hostile path/kind/mode/link/declared-size metadata,
encryption where visible, and an independently classified traversal/absolute/
backslash flag.

Archive identification is informational. Retained traversal/link members form
one aggregate medium fact whose explanation depends on a later unsafe
extractor. Every archive produces a dedicated payload unknown and limitation:
member code, nested containers, compression behavior, and runtime semantics
were not extracted or analyzed. Malformed, excessive, oversized, and overflow
metadata fail without extraction. See
[ADR 0015](decisions/0015-archive-metadata-inventory.md).

## Native ELF files

ELF files use a separate bounded byte budget. The scanner hashes the exact file
and parses class, byte order, architecture, ELF type, interpreter, imported
libraries and undefined dynamic symbols, symbol-table presence, bounded
printable strings, embedded URL strings, Linux file capabilities, and
setuid/setgid mode bits. The pinned descriptor supplies modes and extended
attributes. Binary bytes never enter the source analyzer map.

Every ELF produces a metadata fact, a dedicated unknown record, and an explicit
`native-binary-behavior` limitation. Metadata does not establish executable
behavior, control-flow reachability, network access, or prove that a binary
corresponds to available source. Security-relevant imports, embedded URLs, and
privilege metadata are separate facts with that qualification. Scope is
derived separately from textual runtime reachability.

## Known gaps

- TypeScript, Go, Ruby, Perl, Lua, and PHP do not yet receive syntax-tree
  semantic analysis. Runtime or unknown-scope files
  produce explicit coverage limitations; conventional tooling-only paths do
  not become runtime gaps.
- Filesystem, persistence, credential, and network facts are currently derived
  from recognized process commands; native APIs and constructed values may be
  missed.
- QML property aliases and constructed command arrays can remain dynamic.
- The report schema is versioned but not yet declared stable.

## Python and JavaScript syntax-tree boundary

Python and standalone JavaScript are parsed by pinned pure-Go Tree-sitter
grammar subsets. The production scanner mounts no CPython, Node, shared
library, or grammar file. It records conservative call-expression facts and
source evidence; comments and string lookalikes are negative-tested. Malformed,
timed-out, or early-stopped parses become explicit limitations plus dedicated
`parser-failure` unknowns.

For a reviewed set of Python `subprocess` and JavaScript `child_process`
execution APIs, direct literal strings/arrays and recursively referenced,
single-definition module-level literal assignments produce a separate
`process-execution-via-python` or `process-execution-via-javascript` operation.
JavaScript literal argument arrays are retained as command arguments. These
operations feed the ordinary command capability and correlation stages. An
informational flow fact cites the assignment and call whenever an assignment
was followed.

Branch-local definitions, duplicate definitions, cycles, computed values,
unsupported quoting, missing arguments, and other ambiguous forms remain a
dedicated `unresolved-data-flow` unknown linked to the call. The analyzer cites
bounded identifier use sites and nearest preceding textual assignments only as
origins, not as a claimed runtime flow. Resolution is capped at 16 references
and 1,024 retained assignments; the first over-limit definition produces a
budget limitation and unknown rather than being guessed. Traversal, origin
count, evidence size, and result graph remain independently bounded. This stage
does not claim import resolution,
dynamic-property resolution, branch-sensitive data flow, or equivalence to
language execution semantics.

## Optional Omarchy audit evidence

An explicitly supplied, pinned PR #8439 JSON report is decoded under ADR 0017.
Its commands, hosts, reads, writes, and risks retain `omarchy-audit` provenance
and never replace independent operations. Exact semantic keys create
`corroborates` edges. An observation retained by only one analyzer creates an
informational coverage-disagreement fact and `disagrees-with` edge; this says
the retained sets differ, not that either scanner is correct or exhaustive.

The upstream verdict is validated but not copied into the product verdict.
Because this pinned upstream JSON has no content digest, every import also
creates an explicit snapshot-binding unknown even when plugin IDs match.
