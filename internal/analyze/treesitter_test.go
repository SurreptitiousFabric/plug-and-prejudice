package analyze

import (
	"fmt"
	"strings"
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestPythonSyntaxTreeRecordsCallsButNotCommentOrStringLookalikes(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"helper.py": []byte("# fake.call()\ntext = 'also.fake()'\nsubprocess.run(['whoami'])\n"),
	}))
	if len(result.Operations) != 2 || result.Operations[0].Command != "subprocess.run" || result.Operations[1].Command != "whoami" {
		t.Fatalf("Python operations = %#v", result.Operations)
	}
	if hasLimitationCode(result, "python-semantic-analysis-unavailable") {
		t.Fatalf("successfully parsed Python retained obsolete coverage limitation: %#v", result.Limitations)
	}
}

func TestJavaScriptSyntaxTreeRecordsCallsButNotCommentOrStringLookalikes(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"helper.js": []byte("// fake()\nconst text = 'also.fake()';\nchild_process.execFile('whoami');\n"),
	}))
	if len(result.Operations) != 2 || result.Operations[0].Command != "child_process.execFile" || result.Operations[1].Command != "whoami" {
		t.Fatalf("JavaScript operations = %#v", result.Operations)
	}
}

func TestPythonDynamicProcessArgumentHasBoundedTextualOrigin(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"helper.py": []byte("import subprocess\ncommand = load_command()\nsubprocess.run(command)\n"),
	}))
	if len(result.Unknowns) != 1 || result.Unknowns[0].Reason != report.UnknownUnresolvedFlow || len(result.Unknowns[0].Origins) != 2 {
		t.Fatalf("Python dynamic command unknown = %#v", result.Unknowns)
	}
	if result.Unknowns[0].Origins[0].Kind != report.OriginUseSite || result.Unknowns[0].Origins[0].Name != "command" ||
		result.Unknowns[0].Origins[1].Kind != report.OriginAssignment || result.Unknowns[0].Origins[1].Evidence.LineStart != 2 {
		t.Fatalf("Python runtime origin chain = %#v", result.Unknowns[0].Origins)
	}
	if len(result.Unknowns[0].AffectedOperations) != 1 {
		t.Fatalf("Python unknown is not linked to its call: %#v", result.Unknowns[0])
	}
}

func TestJavaScriptDynamicProcessArgumentHasBoundedTextualOrigin(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"helper.js": []byte("const command = chooseCommand();\nchild_process.execFile(command);\n"),
	}))
	if len(result.Unknowns) != 1 || result.Unknowns[0].Reason != report.UnknownUnresolvedFlow || len(result.Unknowns[0].Origins) != 2 {
		t.Fatalf("JavaScript dynamic command unknown = %#v", result.Unknowns)
	}
	if result.Unknowns[0].Origins[1].Kind != report.OriginAssignment || result.Unknowns[0].Origins[1].Evidence.LineStart != 1 {
		t.Fatalf("JavaScript runtime origin chain = %#v", result.Unknowns[0].Origins)
	}
}

func TestPythonAndJavaScriptLiteralProcessArgumentsRemainResolved(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"helper.py": []byte("import subprocess\nsubprocess.run(['whoami', '--help'])\n"),
		"helper.js": []byte("child_process.spawn('whoami', ['--help']);\n"),
	}))
	if len(result.Unknowns) != 0 {
		t.Fatalf("literal process arguments became unknown: %#v", result.Unknowns)
	}
}

func TestPythonModuleLiteralAssignmentProducesProcessAndNetworkFacts(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"helper.py": []byte("import subprocess\ncommand = ['curl', 'https://api.example.test/v1']\nsubprocess.run(command)\n"),
	}))
	op := operationByCategory(t, result, "process-execution-via-python")
	if op.Command != "curl" || len(op.Arguments) != 1 || op.Arguments[0] != "https://api.example.test/v1" || op.Dynamic {
		t.Fatalf("resolved Python process = %#v", op)
	}
	if !hasFindingCategory(result, "python-literal-process-flow") {
		t.Fatalf("Python flow fact missing: %#v", result.Findings)
	}
	resource := resourceByKind(t, result, "network-domain")
	if resource.Value != "api.example.test" || resource.RelatedOperationID != op.ID {
		t.Fatalf("Python-derived network fact = %#v", resource)
	}
}

func TestJavaScriptModuleLiteralAssignmentsResolveCommandAndArguments(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"helper.js": []byte("const command = 'curl';\nconst args = ['https://js.example.test'];\nchild_process.spawn(command, args);\n"),
	}))
	op := operationByCategory(t, result, "process-execution-via-javascript")
	if op.Command != "curl" || len(op.Arguments) != 1 || op.Arguments[0] != "https://js.example.test" {
		t.Fatalf("resolved JavaScript process = %#v", op)
	}
	if !hasFindingCategory(result, "javascript-literal-process-flow") {
		t.Fatalf("JavaScript flow fact missing: %#v", result.Findings)
	}
}

func TestLanguageLiteralFlowRejectsBranchLocalDuplicateAndComputedDefinitions(t *testing.T) {
	tests := map[string]string{
		"branch.py":    "import subprocess\nif enabled:\n    command = ['first']\nsubprocess.run(command)\n",
		"duplicate.js": "let command = 'first';\ncommand = 'second';\nchild_process.spawn(command);\n",
		"computed.py":  "import subprocess\ncommand = build_command()\nsubprocess.run(command)\n",
	}
	for name, source := range tests {
		result := Sources(withValidManifest(map[string][]byte{name: []byte(source)}))
		for _, operation := range result.Operations {
			if strings.HasPrefix(operation.Category, "process-execution-via-python") || strings.HasPrefix(operation.Category, "process-execution-via-javascript") {
				t.Fatalf("%s guessed literal flow: %#v", name, operation)
			}
		}
		if len(result.Unknowns) == 0 || result.Unknowns[len(result.Unknowns)-1].Reason != report.UnknownUnresolvedFlow {
			t.Fatalf("%s lacks explicit unresolved flow: %#v", name, result.Unknowns)
		}
	}
}

func TestLanguageAssignmentFlowBudgetExactAndFirstOver(t *testing.T) {
	makePython := func(fillers int) []byte {
		var source strings.Builder
		source.WriteString("import subprocess\n")
		for index := 0; index < fillers; index++ {
			fmt.Fprintf(&source, "unused_%d = 'value'\n", index)
		}
		source.WriteString("command = ['whoami']\nsubprocess.run(command)\n")
		return []byte(source.String())
	}
	exact := Sources(withValidManifest(map[string][]byte{"exact.py": makePython(1023)}))
	if hasLimitationCode(exact, "python-assignment-analysis-budget") {
		t.Fatalf("exact assignment limit rejected: %#v", exact.Limitations)
	}
	if operationByCategory(t, exact, "process-execution-via-python").Command != "whoami" {
		t.Fatalf("exact-limit flow not resolved: %#v", exact.Operations)
	}
	over := Sources(withValidManifest(map[string][]byte{"over.py": makePython(1024)}))
	if !hasLimitationCode(over, "python-assignment-analysis-budget") {
		t.Fatalf("first-over assignment limit not reported: %#v", over.Limitations)
	}
	for _, operation := range over.Operations {
		if operation.Category == "process-execution-via-python" {
			t.Fatalf("assignment beyond retained budget was resolved: %#v", operation)
		}
	}
}

func TestBranchingAndCyclicLanguageAssignmentsRemainTextualNotGuessed(t *testing.T) {
	for _, test := range []struct {
		name   string
		source string
	}{
		{"branch.py", "import subprocess\nif enabled:\n    command = first\nelse:\n    command = second\nsubprocess.run(command)\n"},
		{"cycle.js", "let first = second;\nlet second = first;\nchild_process.spawn(first);\n"},
	} {
		result := Sources(withValidManifest(map[string][]byte{test.name: []byte(test.source)}))
		if len(result.Unknowns) != 1 || len(result.Unknowns[0].Origins) != 2 || result.Unknowns[0].Confidence != report.ConfidenceHigh {
			t.Fatalf("%s branching/cyclic unknown = %#v", test.name, result.Unknowns)
		}
		if !strings.Contains(result.Unknowns[0].Description, "not proof of runtime control flow") {
			t.Fatalf("%s overstated textual flow: %#v", test.name, result.Unknowns[0])
		}
	}
}

func TestMalformedPythonBecomesLimitation(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{"helper.py": []byte("def broken(:\n")}))
	if !hasLimitationCode(result, "python-syntax-analysis-incomplete") {
		t.Fatalf("malformed Python limitations = %#v", result.Limitations)
	}
	if len(result.Unknowns) != 1 || result.Unknowns[0].Reason != report.UnknownParserFailure || len(result.Unknowns[0].AffectedOperations) != 0 {
		t.Fatalf("malformed Python did not produce a dedicated parser unknown: %#v", result.Unknowns)
	}
}

func TestNestedDynamicProcessArgumentFindsIdentifierOrigin(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"helper.py": []byte("import subprocess\nargument = load_value()\nsubprocess.run(['tool', argument])\n"),
	}))
	if len(result.Unknowns) != 1 || len(result.Unknowns[0].Origins) < 3 {
		t.Fatalf("nested dynamic argument origins = %#v", result.Unknowns)
	}
	foundAssignment := false
	for _, origin := range result.Unknowns[0].Origins {
		if origin.Kind == report.OriginAssignment && origin.Name == "argument" {
			foundAssignment = true
		}
	}
	if !foundAssignment {
		t.Fatalf("nested identifier assignment was not cited: %#v", result.Unknowns[0].Origins)
	}
}

func TestTreeSitterShebangDetection(t *testing.T) {
	if got := treeSitterLanguage("helper", []byte("#!/usr/bin/env python3\nprint('ok')\n")); got != "python" {
		t.Fatalf("language = %q", got)
	}
}

func operationByCategory(t *testing.T, result Result, category string) report.Operation {
	t.Helper()
	for _, operation := range result.Operations {
		if operation.Category == category {
			return operation
		}
	}
	t.Fatalf("operation category %q missing: %#v", category, result.Operations)
	return report.Operation{}
}

func TestTreeSitterDeepAndLargeInputsRemainBounded(t *testing.T) {
	for _, test := range []struct{ name, source string }{
		{"deep.py", strings.Repeat("(", 5_000) + "1" + strings.Repeat(")", 5_000)},
		{"large.js", strings.Repeat("call();\n", maxProducedOperations+1)},
	} {
		result := Sources(withValidManifest(map[string][]byte{test.name: []byte(test.source)}))
		if len(result.Operations) > maxProducedOperations {
			t.Fatalf("%s produced %d operations", test.name, len(result.Operations))
		}
		assertAnalyzerResult(t, result)
		if test.name == "large.js" && !hasLimitationCode(result, "result-production-limit") && !hasLimitationCode(result, "javascript-syntax-analysis-incomplete") {
			t.Fatalf("large JavaScript omitted no production limitation: %#v", result.Limitations)
		}
	}
}
