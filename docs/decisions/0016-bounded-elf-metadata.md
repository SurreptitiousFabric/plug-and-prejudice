# 0016: Bounded non-executing ELF metadata

- Status: implemented in development tree; independent binary/parser review pending
- Date: 2026-08-28

## Context

An ELF marker and library list expose too little for forensic review, while
loading or executing a plugin binary violates the scanner trust boundary. Raw
strings and imports can also be overinterpreted as behavior.

## Decision

Parse only already bounded ELF bytes with Go's `debug/elf` reader. Retain at
most 1,024 linked libraries, 1,024 undefined dynamic symbols, 256 printable
ASCII strings of six or more bytes, and 128 URL strings. Read setuid/setgid
from descriptor-derived mode metadata and `security.capability` from the pinned
file descriptor. Accept Linux VFS capability revisions 1–3 and retain the
union of permitted and inheritable capability names plus the effective flag.

All collections are charged to the aggregate inventory string budget and
validated independently. Parse failures, unsupported capability encodings,
and truncation produce limitations. Binary bytes never enter language
analysis, and no binary is loaded, imported, disassembled, or executed.

Analysis reports metadata as facts. Privilege metadata, selected
security-relevant imports, and embedded URL strings are qualified observations:
they do not prove reachable calls, arguments, network access, or preserved
installation privileges. Every ELF separately produces a `native-behavior`
unknown and limitation.

## Residual risk and review gate

Printable strings are incomplete, stripped/static binaries reveal less, symbol
versioning and unusual ELF layouts may reduce coverage, and file capabilities
may be dropped by packaging. The standard ELF parser allocates structures from
the bounded input before retained-result caps apply.

Independent human review is required for ELF parsing, capability word/bit
decoding, descriptor identity assumptions, string and URL boundaries,
collection accounting, severities, and non-behavior wording before merge.
