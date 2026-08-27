# Contributing

Start with `AGENTS.md`, `docs/architecture.md`, and `docs/threat-model.md`.

Proposals that change a trust boundary, sandbox policy, report schema, update
model, dependency set, or external-data disclosure require a decision record
and security review before implementation.

Keep changes small and testable. Detection rules must include benign cases as
well as malicious or suspicious cases so that keyword matching does not become
the product's behavior.

Do not commit credentials, private plugin source, copied personal configuration,
or hostile fixtures whose ordinary execution could harm a contributor's system.
