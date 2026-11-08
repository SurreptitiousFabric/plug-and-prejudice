package securitypolicy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	qmlTextObjectPattern = regexp.MustCompile(`\bText\s*\{`)
	qmlPlainTextPattern  = regexp.MustCompile(`(?m)^\s*textFormat:\s*Text\.PlainText\s*$`)
)

func TestEveryProductionTextObjectForcesPlainText(t *testing.T) {
	panel := filepath.Join(repositoryRoot(t), "Panel.qml")
	data, err := os.ReadFile(panel)
	if err != nil {
		t.Fatal(err)
	}
	textObjects := len(qmlTextObjectPattern.FindAll(data, -1))
	plainTextModes := len(qmlPlainTextPattern.FindAll(data, -1))
	if textObjects == 0 || plainTextModes != textObjects {
		t.Fatalf("Panel.qml has %d Text objects but %d explicit Text.PlainText modes", textObjects, plainTextModes)
	}
}

func TestProductionPlainTextNormalizerCoversUnicodeBidiControls(t *testing.T) {
	panel := filepath.Join(repositoryRoot(t), "Panel.qml")
	data, err := os.ReadFile(panel)
	if err != nil {
		t.Fatal(err)
	}
	policy := string(data)
	for _, escaped := range []string{`\u061c`, `\u200e`, `\u200f`, `\u202a-\u202e`, `\u2066-\u2069`} {
		if !strings.Contains(policy, escaped) {
			t.Errorf("Panel.qml plain-text normalizer omits %s", escaped)
		}
	}
}

func TestProductionPanelExposesBoundedCommandsSection(t *testing.T) {
	panel := filepath.Join(repositoryRoot(t), "Panel.qml")
	data, err := os.ReadFile(panel)
	if err != nil {
		t.Fatal(err)
	}
	contract := string(data)
	for _, required := range []string{
		`property var visibleOperations: []`,
		`["Findings", "Commands", "Resources", "Limits"]`,
		`visibleOperations = parsed.operations.slice(0, 500)`,
		`setVisibleFindings(parsed.findings)`,
		`setVisibleResources(parsed.resources)`,
		`var severities = ["critical", "high", "medium", "low", "informational"]`,
		`if (resources[i].sensitive === true) sensitive.push(resources[i])`,
		`model: 4`,
		`root.rowEvidence(findingRow.modelData)`,
	} {
		if !strings.Contains(contract, required) {
			t.Errorf("Panel.qml omits Commands contract fragment %q", required)
		}
	}
}

func TestProductionPanelExposesBoundedErrorsAndUnknowns(t *testing.T) {
	panel := filepath.Join(repositoryRoot(t), "Panel.qml")
	data, err := os.ReadFile(panel)
	if err != nil {
		t.Fatal(err)
	}
	contract := string(data)
	for _, required := range []string{
		`property var visibleErrors: []`,
		`property var visibleBehaviorUnknowns: []`,
		`setVisibleUnknowns(parsed.unknowns, parsed.limitations, parsed.errors)`,
		`var maximum = 500`,
		`visibleErrors.concat(visibleBehaviorUnknowns).concat(visibleLimitations)`,
		`if (row.reason !== undefined) return "UNKNOWN · "`,
	} {
		if !strings.Contains(contract, required) {
			t.Errorf("Panel.qml omits Limits contract fragment %q", required)
		}
	}
}

func TestProductionPanelSeparatesInlineMetadataFromMultilineEvidence(t *testing.T) {
	panel := filepath.Join(repositoryRoot(t), "Panel.qml")
	data, err := os.ReadFile(panel)
	if err != nil {
		t.Fatal(err)
	}
	contract := string(data)
	for _, required := range []string{
		`function plainInline(value, limit)`,
		`.replace(/[\t\n\r]+/g, " ")`,
		`plainInline(row.title, 240)`,
		`plainInline(row.command || "<unknown>", 240)`,
		`plainInline(evidence.path, 240)`,
		`function authorClaimLabel()`,
		`function authorClaimDescription()`,
		`AUTHOR CLAIM · KINDS · `,
		`maximumLineCount: 2`,
	} {
		if !strings.Contains(contract, required) {
			t.Errorf("Panel.qml omits inline metadata boundary fragment %q", required)
		}
	}
}

func TestTextObjectGuardRecognizesInlineDeclarations(t *testing.T) {
	if !qmlTextObjectPattern.MatchString(`Item { Text { text: hostile } }`) {
		t.Fatal("inline Text declaration escaped the structural guard")
	}
}
