package analyze

import (
	"strings"
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestDesktopEntryRecordsLiteralExecWithoutCallingItAutostart(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"applications/example.desktop": []byte("[Desktop Entry]\nType=Application\nExec=\"/usr/bin/example tool\" --check\n"),
	}))
	if len(result.Operations) != 1 || result.Operations[0].Command != "/usr/bin/example tool" || result.Operations[0].Dynamic || result.Operations[0].Category != "process-execution-via-desktop-entry" {
		t.Fatalf("desktop operation = %#v", result.Operations)
	}
	if hasFindingCategory(result, "persistence") || len(result.Unknowns) != 0 {
		t.Fatalf("ordinary desktop entry became persistence/unknown: %#v", result)
	}
}

func TestAutostartDesktopEntryCorrelatesLaunchAndCapabilities(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"config/autostart/fetch.desktop": []byte("[Desktop Entry]\nType=Application\nExec=curl https://example.test/payload\n"),
	}))
	if !hasFindingCategory(result, "persistence") {
		t.Fatalf("autostart persistence fact missing: %#v", result.Findings)
	}
	foundDomain := false
	for _, resource := range result.Resources {
		if resource.Kind == "network-domain" && resource.Value == "example.test" {
			foundDomain = true
		}
	}
	if !foundDomain {
		t.Fatalf("desktop Exec capability was not derived: %#v", result.Resources)
	}
}

func TestHiddenAutostartAndDesktopLookalikesDoNotBecomePersistence(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"config/autostart/hidden.desktop": []byte("# Exec=sudo\n[Other]\nExec=pkexec\n[Desktop Entry]\nExec[fr]=sudo\nExec=whoami\nHidden=true\n"),
	}))
	if len(result.Operations) != 1 || result.Operations[0].Command != "whoami" || hasFindingCategory(result, "persistence") {
		t.Fatalf("desktop lookalike/hidden handling = %#v", result)
	}
}

func TestDesktopDynamicFieldCodeIsExplicitUnknown(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"applications/open.desktop": []byte("[Desktop Entry]\nExec=viewer %F\n"),
	}))
	if len(result.Operations) != 1 || !result.Operations[0].Dynamic || len(result.Unknowns) != 1 || result.Unknowns[0].Reason != report.UnknownDynamicValue || len(result.Unknowns[0].AffectedOperations) != 1 {
		t.Fatalf("desktop field-code unknown = %#v", result)
	}
}

func TestDesktopEscapedPercentIsNotRuntimeSubstitution(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"applications/percent.desktop": []byte("[Desktop Entry]\nExec=viewer %%\n"),
	}))
	if len(result.Operations) != 1 || result.Operations[0].Dynamic || len(result.Unknowns) != 0 || len(result.Operations[0].Arguments) != 1 || result.Operations[0].Arguments[0] != "%" {
		t.Fatalf("escaped desktop percent became dynamic: %#v", result)
	}
}

func TestDesktopDuplicateAndMalformedExecFailWithoutGuessing(t *testing.T) {
	for _, test := range []struct {
		name   string
		source string
	}{
		{"duplicate.desktop", "[Desktop Entry]\nExec=first\nExec=second\nExec=third\n"},
		{"malformed.desktop", "[Desktop Entry]\nExec=\"unterminated\n"},
	} {
		result := Sources(withValidManifest(map[string][]byte{test.name: []byte(test.source)}))
		if len(result.Operations) != 0 || len(result.Unknowns) != 1 || result.Unknowns[0].Reason != report.UnknownUnsupportedSyntax {
			t.Fatalf("%s guessed an ambiguous command: %#v", test.name, result)
		}
		assertAnalyzerResult(t, result)
	}
}

func TestDesktopLineTraversalIsBounded(t *testing.T) {
	source := "[Desktop Entry]\n" + strings.Repeat("Comment=x\n", maxDesktopLines)
	result := Sources(withValidManifest(map[string][]byte{"large.desktop": []byte(source)}))
	if len(result.Unknowns) != 1 || result.Unknowns[0].Reason != report.UnknownBudgetExhaustion || !hasLimitationCode(result, "desktop-entry-line-budget") {
		t.Fatalf("desktop line budget was not explicit: %#v", result)
	}
	assertAnalyzerResult(t, result)
}

func TestDesktopInvalidTextFailsClosed(t *testing.T) {
	for _, data := range [][]byte{{'[', 0xff, ']'}, []byte("[Desktop Entry]\x00\nExec=sudo\n")} {
		result := Sources(withValidManifest(map[string][]byte{"invalid.desktop": data}))
		if len(result.Operations) != 0 || len(result.Unknowns) != 1 || result.Unknowns[0].Reason != report.UnknownParserFailure || !hasLimitationCode(result, "desktop-entry-invalid-text") {
			t.Fatalf("invalid desktop text did not fail closed: %#v", result)
		}
	}
}
