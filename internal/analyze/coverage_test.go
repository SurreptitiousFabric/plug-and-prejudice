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
