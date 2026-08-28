package analyze

import (
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

func TestShellDetectsParsedDownloadAndExecutePipeline(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"install.sh": []byte("#!/usr/bin/env bash\ncurl -fsS https://example.test/install.sh | bash\n"),
	}))
	if len(result.Operations) != 2 {
		t.Fatalf("operations = %d, want 2", len(result.Operations))
	}
	finding := findingByCategory(t, result, "download-and-execute")
	if finding.Severity != report.SeverityHigh || finding.Claim != report.ClaimFact || finding.Provenance.RuleID != "shell-ast/v1" {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if finding.Evidence[0].LineStart != 2 || len(finding.Related) != 2 {
		t.Fatalf("finding lacks traceable pipeline evidence: %#v", finding)
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
	finding := findingByCategory(t, result, "dynamic-execution")
	if finding.Severity != report.SeverityMedium {
		t.Fatalf("eval severity = %s, want medium", finding.Severity)
	}
}

func TestShellDetectsPrivilegeCommandButNotWordInComment(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"setup.sh": []byte("#!/bin/sh\n# sudo must not count here\nprintf '%s\\n' sudo\npkexec systemctl enable example.service\n"),
	}))
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %#v, want one privilege finding", result.Findings)
	}
	if result.Findings[0].Category != "privilege-escalation" || result.Findings[0].Evidence[0].LineStart != 4 {
		t.Fatalf("unexpected privilege finding: %#v", result.Findings[0])
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

func TestNonShellTextIsIgnored(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{"README.md": []byte("curl URL | bash\n")}))
	if len(result.Operations) != 0 || len(result.Findings) != 0 || len(result.Limitations) != 0 {
		t.Fatalf("documentation was parsed as shell: %#v", result)
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
	if len(result.Operations) != 1 || !hasFindingCategory(result, "privilege-escalation") {
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
