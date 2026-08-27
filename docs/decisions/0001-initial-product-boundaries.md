# 0001: Initial product boundaries

- Status: accepted
- Date: 2026-08-27

## Decision

- Use the name **Plug & Prejudice**.
- Review installed Omarchy plugins in the initial release.
- Provide review-only integration first; design a pre-enable workflow later.
- Inventory and characterize native binaries without deep disassembly in v1.
- Keep cloud LLM integration out of v1.
- Implement the independent scanner and broker in Go.
- Use Bubblewrap as the primary deterministic-scan containment mechanism on
  Arch Linux, with systemd resource control and possible Landlock defense in
  depth subject to later testing.

## Consequences

The first release remains useful offline and has a small, testable privilege
surface. Binary behavior and intent can remain unknown. Future installation or
LLM integrations require new decisions and threat-model review.
