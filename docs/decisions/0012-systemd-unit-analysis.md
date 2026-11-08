# 0012: Bounded systemd unit and activation analysis

- Status: implemented in development tree; independent parser and rule review pending
- Date: 2026-08-28

## Context

Systemd services, timers, paths, sockets, and enablement metadata can connect a
small configuration file to long-lived or event-triggered execution. Searching
for command names loses those relationships. Asking `systemd-analyze`,
`systemctl`, or a shell to interpret hostile unit content would execute a much
larger trusted-computing surface and violate the networkless deterministic
scanner boundary.

## Decision

Parse recognized unit extensions and service/socket/timer/path drop-ins with a
small inert reader. It accepts bounded physical and continued logical lines,
exact section/key names, comments, empty execution-list resets, single/double
quotes, backslash escaping, and the reviewed systemd execution-prefix surface.
It never invokes systemd, a shell, an interpreter, or a configured executable.

Reviewed `Exec*` directives become `process-execution-via-systemd-unit`
operations. Literal commands reuse shared capability extraction. Environment
substitution and non-literal `%` specifiers become linked `dynamic-value`
unknowns; `%%` remains literal, and the `:` execution prefix suppresses
environment expansion as systemd specifies. `+`/`!` privilege-relaxing
prefixes produce a high direct fact with an explanation that actual authority
depends on manager and unit context.

`WantedBy` and `RequiredBy` are retained as informational install-metadata
facts. They do not independently prove persistence. When the same unit also
contains configured execution, a medium inference links enablement metadata to
the execution operations and explicitly leaves installation, enablement,
activation, and success unestablished.

Timer, path, and socket activation directives are informational trigger facts.
An exact safe `Unit=` name, or the systemd default same-basename `.service`, can
be joined to an inspected service in the same target-relative directory. The
result is a medium `triggered-service-execution` inference citing trigger,
reference, and execution operation IDs. Dynamic, path-like, missing, and
non-service references are never guessed.

An exact one-source file-transfer operation may also connect a retained unit
artifact to an exact persistent unit-file destination and the `Exec*`
operations parsed from that precise source. Extensions must be compatible.
Ambiguous source resolution becomes an unknown, and the relationship does not
establish transfer success, installation, manager loading, enablement,
activation, or execution.

Inline shell programs receive the existing parsed adjacent-pipeline checks.
Inline Python/Node programs are retained as evidence but produce an explicit
unknown and limitation rather than being reinterpreted as shell or executed.

## Limits and hostile input

The reader consumes only inventory-retained bytes and has a 20,000 physical-line
limit plus shared operation, argument, evidence, unknown, relationship, encoded
string, and output budgets. Invalid UTF-8, NUL bytes, unfinished continuation,
malformed quoting, oversized tokens, line exhaustion, and unsupported inline
semantics become explicit unknowns/limitations. Tests cover positive,
negative, false-positive, repeated-command, reset, continuation, malformed,
invalid-text, substitution, privilege, safe/unsafe relationship, oversized,
line-budget, deterministic, race, and fuzz behavior.

## Residual risk and review gate

This is not a complete reimplementation of systemd's unit loader. It does not
model every directive, manager search path, drop-in precedence, template
instance, dependency transaction, condition, credential, namespace, or
manager-specific behavior. Same-directory joins describe visible configuration
relationships, not host installation state. System and user managers imply
different authority that target-relative source alone may not establish.

Independent human review is required for unit recognition, continuation and
token semantics, execution prefixes, enablement severity, activation joins,
inline-program boundaries, hostile-input accounting, and all new correlation
language before merge.
