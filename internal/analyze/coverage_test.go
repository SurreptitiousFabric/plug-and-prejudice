package analyze

import (
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestRuntimePythonCreatesExplicitCoverageLimitation(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Runtime.qml": []byte("property string helper: \"helper.py\"\n"),
		"helper.py":   []byte("import subprocess\nsubprocess.run(['whoami'])\n"),
	}))
	limitation := limitationByCode(t, result, "python-semantic-analysis-unavailable")
	if limitation.Path != "helper.py" || limitation.Scope != report.ScopeRuntime {
		t.Fatalf("runtime Python gap not scoped: %#v", limitation)
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

func TestRuntimeJavaScriptCreatesExplicitCoverageLimitation(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"Runtime.qml": []byte("property string model: \"Model.js\"\n"),
		"Model.js":    []byte("function endpoint() { return 'https://example.test' }\n"),
	}))
	limitation := limitationByCode(t, result, "javascript-semantic-analysis-unavailable")
	if limitation.Scope != report.ScopeRuntime {
		t.Fatalf("runtime JavaScript gap not scoped: %#v", limitation)
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
