#!/usr/bin/env python3
"""Turn `go test -json` output into explicit live-containment evidence."""

import json
import os
import sys
from pathlib import Path

EXPECTED = {
    "github.com/SurreptitiousFabric/plug-and-prejudice/cmd/plug-prejudice-broker": [
        "TestLiveBrokerListOverflowFailsInsideResourceScope",
    ],
    "github.com/SurreptitiousFabric/plug-and-prejudice/internal/resource": [
        "TestLiveSystemdScopeEnforcesVerifiableControls",
        "TestLiveSystemdScopeEnforcesMemoryMax",
        "TestLiveSystemdScopeEnforcesTasksMax",
        "TestLiveSystemdScopeKillsSurvivingDescendant",
    ],
    "github.com/SurreptitiousFabric/plug-and-prejudice/internal/sandbox": [
        "TestBubblewrapIsolation",
        "TestBubblewrapBoundsDescendantHoldingOutputDescriptors",
        "TestBubblewrapBoundsSimultaneousStdoutAndStderrExhaustion",
        "TestBubblewrapBoundsAsymmetricOutputExhaustionWithRetainedPipe",
        "TestBubblewrapWallClockTimeout",
        "TestBubblewrapRejectsOversizedOutput",
    ],
}


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: summarize-live-containment-tests.py RAW_JSON RESULT_JSON SUMMARY_MD", file=sys.stderr)
        return 2
    raw, result_path, summary_path = map(Path, sys.argv[1:])
    statuses = {(package, test): "did_not_build" for package, tests in EXPECTED.items() for test in tests}
    reasons = {}
    output = {key: [] for key in statuses}
    for line in raw.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        key = (event.get("Package"), event.get("Test"))
        if key not in statuses:
            continue
        action = event.get("Action")
        if action in {"pass", "fail", "skip"}:
            statuses[key] = action
        if action == "output":
            output[key].append(event.get("Output", "").strip())

    for key, status in statuses.items():
        if status == "skip":
            reasons[key] = " ".join(part for part in output[key] if part and "--- SKIP:" not in part)

    arch = os.environ.get("RUNNER_ARCH", "unknown")
    result = {
        "architecture": arch,
        "required_live_mode": os.environ.get("REQUIRE_LIVE_CONTAINMENT") == "1",
        "tests": [
            {"package": package, "test": test, "status": status, "reason": reasons.get((package, test), "")}
            for (package, test), status in sorted(statuses.items())
        ],
    }
    result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    rows = [
        f"### Live containment evidence ({arch})",
        "",
        "Unit/static coverage is reported by the ordinary test steps. This table records only tests requiring live systemd or Bubblewrap behavior.",
        "",
        "| Test | Status | Skip reason |",
        "|---|---|---|",
    ]
    for entry in result["tests"]:
        reason = entry["reason"].replace("|", "\\|")
        rows.append(f"| `{entry['test']}` | **{entry['status']}** | {reason} |")
    summary_path.write_text("\n".join(rows) + "\n", encoding="utf-8")

    invalid = {"fail", "did_not_build"}
    if result["required_live_mode"]:
        invalid.add("skip")
    return 1 if any(entry["status"] in invalid for entry in result["tests"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
