package analyze

import (
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestRuntimePythonReceivesSyntaxTreeAnalysis(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Runtime.qml": []byte("property string helper: \"helper.py\"\n"),
		"helper.py":   []byte("import subprocess\nsubprocess.run(['whoami'])\n"),
	}))
	if len(result.Operations) != 2 || result.Operations[0].Command != "subprocess.run" || result.Operations[1].Command != "whoami" || result.Operations[1].Scope != report.ScopeRuntime {
		t.Fatalf("runtime Python operations = %#v", result.Operations)
	}
}

func TestCoverageSummaryUsesExplicitSupportedArtifactFileUnits(t *testing.T) {
	files := []report.File{
		{Path: "manifest.json", Kind: "regular", Inspected: true},
		{Path: "Panel.qml", Kind: "regular", Inspected: true},
		{Path: "helper.go", Kind: "regular", Inspected: true},
		{Path: "helper.elf", Kind: "regular", Inspected: true, Binary: &report.Binary{Format: "ELF"}},
		{Path: "oversized.js", Kind: "regular", Inspected: false},
		{Path: "README.md", Kind: "regular", Inspected: true},
	}
	contents := map[string][]byte{"manifest.json": []byte("{}"), "Panel.qml": []byte("Item {}"), "helper.go": []byte("package main"), "README.md": []byte("text")}
	coverage := SummarizeCoverage(files, contents, []report.Limitation{{Code: "qml", Description: "partial", Path: "Panel.qml"}}, nil)
	if coverage.AnalyzedUnits != 1 || coverage.PartialUnits != 2 || coverage.UnanalyzedUnits != 2 || coverage.TotalUnits != 5 || coverage.Percentage == nil || *coverage.Percentage != 20 || coverage.Level != "partial" {
		t.Fatalf("coverage = %#v", coverage)
	}
}

func TestCoverageSummaryDoesNotPublishPercentageWithoutEligibleUnits(t *testing.T) {
	coverage := SummarizeCoverage([]report.File{{Path: "README.md", Kind: "regular", Inspected: true}}, map[string][]byte{"README.md": []byte("text")}, nil, nil)
	if coverage.TotalUnits != 0 || coverage.Percentage != nil || coverage.Level != "not-applicable" {
		t.Fatalf("empty coverage = %#v", coverage)
	}
}

func TestToolingPythonDoesNotMakeRuntimeCoverageIncomplete(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"tests/generate_fixture.py": []byte("print('fixture')\n"),
	}))
	for _, limitation := range result.Limitations {
		if limitation.Code == "python-semantic-analysis-unavailable" {
			t.Fatalf("tooling-only Python created runtime coverage gap: %#v", limitation)
		}
	}
}

func TestRuntimeJavaScriptReceivesSyntaxTreeAnalysis(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Runtime.qml": []byte("property string model: \"Model.js\"\n"),
		"Model.js":    []byte("function endpoint() { return fetch('https://example.test') }\n"),
	}))
	if len(result.Operations) != 1 || result.Operations[0].Command != "fetch" || result.Operations[0].Scope != report.ScopeRuntime {
		t.Fatalf("runtime JavaScript operations = %#v", result.Operations)
	}
}

func TestUnparsedRuntimeLanguagesCreateCoverageLimitations(t *testing.T) {
	tests := []struct {
		name string
		path string
		code string
	}{
		{name: "Go", path: "helper.go", code: "go-semantic-analysis-unavailable"},
		{name: "TypeScript", path: "helper.ts", code: "typescript-semantic-analysis-unavailable"},
		{name: "Ruby shebang", path: "helper", code: "ruby-semantic-analysis-unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := []byte("package main\n")
			if test.name == "Ruby shebang" {
				body = []byte("#!/usr/bin/env ruby\nputs 'hello'\n")
			}
			result := Sources(withValidManifest(map[string][]byte{
				"Runtime.qml": []byte("property string helper: \"" + test.path + "\"\n"),
				test.path:     body,
			}))
			limitation := limitationByCode(t, result, test.code)
			if limitation.Scope != report.ScopeRuntime {
				t.Fatalf("runtime language gap not scoped: %#v", limitation)
			}
		})
	}
}

func TestToolingGoDoesNotCreateRuntimeLimitation(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"tests/helper.go": []byte("package tests\n"),
	}))
	for _, limitation := range result.Limitations {
		if limitation.Code == "go-semantic-analysis-unavailable" {
			t.Fatalf("tooling-only Go created runtime coverage gap: %#v", limitation)
		}
	}
}

func TestUnreferencedGoCoverageScopeRemainsUnknown(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Runtime.qml": []byte("Item {}\n"),
		"helper.go":   []byte("package main\n"),
	}))
	limitation := limitationByCode(t, result, "go-semantic-analysis-unavailable")
	if limitation.Scope != report.ScopeUnknown {
		t.Fatalf("unreferenced Go source scope = %q, want unknown", limitation.Scope)
	}
}

func limitationByCode(t *testing.T, result Result, code string) report.Limitation {
	t.Helper()
	for _, limitation := range result.Limitations {
		if limitation.Code == code {
			return limitation
		}
	}
	t.Fatalf("missing %s limitation in %#v", code, result.Limitations)
	return report.Limitation{}
}
