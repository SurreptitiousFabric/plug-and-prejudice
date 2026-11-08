package analyze

import (
	"strings"
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestCopiedDesktopArtifactConnectsPersistentDestinationToDeclaredCommand(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"install.sh":           []byte("cp assets/agent.desktop ~/.config/autostart/agent.desktop\n"),
		"assets/agent.desktop": []byte("[Desktop Entry]\nExec=python3 ./agent.py\n"),
	}))
	finding := findingByCategory(t, result, "installed-startup-artifact-execution")
	if finding.Claim != report.ClaimInference || finding.Severity != report.SeverityMedium || finding.Confidence != report.ConfidenceMedium ||
		len(finding.Related) != 2 || finding.Provenance.RuleID != installedArtifactRuleID || !strings.Contains(finding.Explanation, "does not establish") {
		t.Fatalf("installed desktop relationship = %#v", finding)
	}
	assertRelatedOperationsExist(t, result, finding)
}

func TestInstalledSystemdArtifactConnectsTransferToConfiguredExecution(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"install.sh":          []byte("install -m644 units/agent.service ~/.config/systemd/user/agent.service\n"),
		"units/agent.service": []byte("[Service]\nExecStart=/usr/bin/agent --serve\n"),
	}))
	finding := findingByCategory(t, result, "installed-startup-artifact-execution")
	if len(finding.Related) != 2 || !strings.Contains(finding.Explanation, "units/agent.service") {
		t.Fatalf("installed unit relationship = %#v", finding)
	}
}

func TestInstalledArtifactCorrelationRequiresExactOneToOneVisibleFlow(t *testing.T) {
	cases := []map[string][]byte{
		{"install.sh": []byte("cp one.desktop two.desktop ~/.config/autostart/result.desktop\n"), "one.desktop": []byte("[Desktop Entry]\nExec=one\n"), "two.desktop": []byte("[Desktop Entry]\nExec=two\n")},
		{"install.sh": []byte("cp agent.desktop ~/.config/autostart/\n"), "agent.desktop": []byte("[Desktop Entry]\nExec=agent\n")},
		{"install.sh": []byte("cp agent.desktop ./ordinary.desktop\n"), "agent.desktop": []byte("[Desktop Entry]\nExec=agent\n")},
		{"install.sh": []byte("cp notes.txt ~/.config/autostart/agent.desktop\n"), "notes.txt": []byte("Exec=agent\n")},
	}
	for _, contents := range cases {
		result := Sources(withValidManifest(contents))
		if hasFindingCategory(result, "installed-startup-artifact-execution") {
			t.Fatalf("unestablished artifact flow was correlated: %#v", result.Findings)
		}
	}
}

func TestAmbiguousInstalledArtifactSourceBecomesUnknown(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{
		"task.desktop":         []byte("[Desktop Entry]\nExec=root-task\n"),
		"scripts/task.desktop": []byte("[Desktop Entry]\nExec=local-task\n"),
		"scripts/install.sh":   []byte("cp task.desktop ~/.config/autostart/task.desktop\n"),
	}))
	foundUnknown := false
	for _, unknown := range result.Unknowns {
		foundUnknown = foundUnknown || unknown.Reason == report.UnknownUnresolvedFlow
	}
	if hasFindingCategory(result, "installed-startup-artifact-execution") || !foundUnknown {
		t.Fatalf("ambiguous installed artifact did not remain unknown: %#v", result)
	}
	unknown := result.Unknowns[0]
	if len(unknown.SuppressedRules) != 1 || unknown.SuppressedRules[0] != installedArtifactRuleID || len(unknown.AffectedOperations) != 1 {
		t.Fatalf("ambiguous installed artifact provenance = %#v", unknown)
	}
}
