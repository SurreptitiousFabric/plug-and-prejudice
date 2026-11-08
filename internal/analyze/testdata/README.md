# Static analysis fixtures

Everything below this directory is hostile **data**, not a runnable test.
Fixture scripts must remain non-executable. Go tests read their bytes with
`os.ReadFile` and pass them directly to the deterministic analyzer; they never
source, import, spawn, or otherwise execute a fixture.

The test harness rejects symbolic links, special files, executable permission
bits, and individual fixture files above 64 KiB across the entire directory,
including files not yet referenced by a scenario assertion.

`hostile-combined/install.sh` deliberately contains destructive-looking shell
text. Do not run it.

The single-purpose directories exercise network access, filesystem writes,
credential reads, privilege escalation, deletion, persistence, dynamic or
obfuscated shell execution, QML subprocesses, and legitimate contextual uses
of potentially dangerous commands. Scenario tests assert facts, evidence,
scope, severity, explicit limitations, and false-positive handling.
