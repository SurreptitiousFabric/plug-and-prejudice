package securitypolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectionRulePlaybookNamesCurrentBoundaries(t *testing.T) {
	root := repositoryRoot(t)
	playbookPath := filepath.Join(root, "docs", "detection-rules.md")
	data, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatal(err)
	}
	playbook := string(data)
	for _, required := range []string{
		"operations[]",
		"resources[]",
		"`findings[]` with `fact`",
		"`findings[]` with `inference`",
		"limitations[]",
		"internal/analyze.Sources",
		"internal/analyze.Inventory",
		"comments, strings, similarly named commands",
		"never invoked",
		"No target byte reaches process execution",
	} {
		if !strings.Contains(playbook, required) {
			t.Errorf("detection rule playbook omits required boundary %q", required)
		}
	}

	for _, relative := range []string{
		"internal/analyze/capabilities.go",
		"internal/analyze/coverage.go",
		"internal/analyze/manifest.go",
		"internal/analyze/qml.go",
		"internal/analyze/scope.go",
		"internal/analyze/shell.go",
		"internal/analyze/scenarios_test.go",
		"internal/report",
	} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(relative))); err != nil {
			t.Errorf("documented analyzer boundary %s is unavailable: %v", relative, err)
		}
	}
}

func TestContributorEntrypointsLinkDetectionRulePlaybook(t *testing.T) {
	root := repositoryRoot(t)
	for _, relative := range []string{"README.md", "CONTRIBUTING.md", "docs/development.md"} {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "detection-rules.md") {
			t.Errorf("%s does not link the deterministic rule playbook", relative)
		}
	}
}
