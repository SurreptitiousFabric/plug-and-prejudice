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

Run the deterministic checks with:

```bash
go test ./...
go test -race ./...
go vet ./...
go mod verify
scripts/test-qml.sh
```

`scripts/test-installed-integration.sh` is deliberately separate because it
reviews a real installed plugin. Set `PLUG_PREJUDICE_TEST_PLUGIN` to an installed
plugin ID to select the target. The test invokes only the trusted reviewer and
passes the target to the scanner as data through the normal Bubblewrap policy.
Never point ordinary test discovery at executable hostile fixtures.
