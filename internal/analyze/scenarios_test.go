package analyze

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

const maxScenarioFixtureBytes = 64 << 10

func TestAllScenarioFixtureFilesAreBoundedInertData(t *testing.T) {
	err := filepath.WalkDir("testdata", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		return validateFixtureEntry(path, entry)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestScenarioFixturesRemainInertAndExplainContext(t *testing.T) {
	t.Run("harmless", func(t *testing.T) {
		result := Sources(loadScenario(t, "harmless"))
		if len(result.Operations) != 0 || len(result.Resources) != 0 || len(result.Findings) != 0 || len(result.Limitations) != 0 {
			t.Fatalf("harmless fixture produced security behavior: %#v", result)
		}
	})

	t.Run("legitimate network", func(t *testing.T) {
		result := Sources(loadScenario(t, "legitimate-network"))
		resource := resourceByKind(t, result, "network-domain")
		if resource.Value != "status.example.test" || resource.Access != "connect" || resource.Scope != report.ScopeRuntime {
			t.Fatalf("network fact lost its context: %#v", resource)
		}
		if len(result.Findings) != 0 {
			t.Fatalf("ordinary download became a warning: %#v", result.Findings)
		}
	})

	t.Run("hostile combined", func(t *testing.T) {
		result := Sources(loadScenario(t, "hostile-combined"))
		want := map[string]report.Severity{
			"credential-access":     report.SeverityHigh,
			"destructive-operation": report.SeverityCritical,
			"download-and-execute":  report.SeverityHigh,
			"dynamic-execution":     report.SeverityMedium,
			"persistence":           report.SeverityMedium,
			"privilege-escalation":  report.SeverityHigh,
		}
		seen := make(map[string]report.Severity)
		for _, finding := range result.Findings {
			seen[finding.Category] = finding.Severity
			if (finding.Claim != report.ClaimFact && finding.Claim != report.ClaimInference && finding.Claim != report.ClaimUnknown) ||
				finding.Provenance.RuleID == "" || len(finding.Evidence) == 0 {
				t.Fatalf("finding lacks valid claim, provenance, or evidence: %#v", finding)
			}
		}
		for category, severity := range want {
			if seen[category] != severity {
				t.Errorf("%s severity = %q, want %q; findings: %#v", category, seen[category], severity, result.Findings)
			}
		}
	})

	for _, scenario := range []struct {
		name       string
		category   string
		severity   report.Severity
		resource   string
		access     string
		limitation string
	}{
		{name: "credential-read", category: "credential-access", severity: report.SeverityHigh, resource: "filesystem-path", access: "read"},
		{name: "privilege-escalation", category: "privilege-escalation", severity: report.SeverityHigh},
		{name: "recursive-cache-delete", category: "destructive-operation", severity: report.SeverityMedium, resource: "filesystem-path", access: "delete"},
		{name: "persistence", category: "persistence", severity: report.SeverityMedium, resource: "persistence", access: "modify"},
		{name: "suspicious-subprocess", category: "dynamic-execution", severity: report.SeverityMedium, limitation: "inline-dynamic-language-analysis-unavailable"},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			result := Sources(loadScenario(t, scenario.name))
			finding := findingByCategory(t, result, scenario.category)
			if finding.Severity != scenario.severity || finding.Claim != report.ClaimFact ||
				finding.Provenance.RuleID == "" || len(finding.Evidence) == 0 || len(finding.Related) == 0 || finding.Scope != report.ScopeRuntime {
				t.Fatalf("scenario finding lost context: %#v", finding)
			}
			if scenario.resource != "" {
				resource := resourceByKind(t, result, scenario.resource)
				if resource.Access != scenario.access || resource.Scope != report.ScopeRuntime || resource.RelatedOperationID == "" {
					t.Fatalf("scenario resource lost context: %#v", resource)
				}
			}
			if scenario.limitation != "" && !hasLimitationCode(result, scenario.limitation) {
				t.Fatalf("scenario omitted %s limitation: %#v", scenario.limitation, result.Limitations)
			}
		})
	}

	t.Run("obfuscated dynamic shell", func(t *testing.T) {
		result := Sources(loadScenario(t, "obfuscated-dynamic-shell"))
		if !hasFindingCategory(result, "dynamic-execution") {
			t.Fatalf("eval fact was omitted: %#v", result.Findings)
		}
		inference := findingByCategory(t, result, "obfuscated-execution")
		if inference.Claim != report.ClaimInference || inference.Severity != report.SeverityMedium ||
			inference.Confidence != report.ConfidenceMedium || inference.Scope != report.ScopeRuntime ||
			len(inference.Evidence) != 2 || len(inference.Related) != 2 {
			t.Fatalf("obfuscation inference lost uncertainty or traceability: %#v", inference)
		}
	})

	t.Run("filesystem write", func(t *testing.T) {
		result := Sources(loadScenario(t, "filesystem-write"))
		resource := resourceByKind(t, result, "filesystem-path")
		if resource.Access != "write" || resource.Value != "~/.config/example-plugin" || resource.Sensitive || resource.Scope != report.ScopeRuntime {
			t.Fatalf("filesystem write fact lost context: %#v", resource)
		}
		if len(result.Findings) != 0 {
			t.Fatalf("ordinary configuration write became a warning: %#v", result.Findings)
		}
	})

	t.Run("legitimate dangerous commands", func(t *testing.T) {
		result := Sources(loadScenario(t, "legitimate-dangerous-commands"))
		deletion := findingByCategory(t, result, "destructive-operation")
		if deletion.Severity != report.SeverityLow || deletion.Scope != report.ScopeRuntime {
			t.Fatalf("ordinary literal deletion severity lost context: %#v", deletion)
		}
		for _, absent := range []string{"download-and-execute", "persistence", "privilege-escalation"} {
			if hasFindingCategory(result, absent) {
				t.Fatalf("legitimate command use produced %s: %#v", absent, result.Findings)
			}
		}
	})
}

func loadScenario(t *testing.T, name string) map[string][]byte {
	t.Helper()
	root := filepath.Join("testdata", name)
	contents := make(map[string][]byte)
	err := filepath.WalkDir(root, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := validateFixtureEntry(filePath, entry); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, filePath)
		if err != nil {
			return err
		}
		contents[filepath.ToSlash(relative)] = data
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) == 0 {
		t.Fatalf("scenario %q is empty", name)
	}
	return contents
}

func validateFixtureEntry(path string, entry fs.DirEntry) error {
	if entry.IsDir() {
		return nil
	}
	info, err := entry.Info()
	if err != nil {
		return fmt.Errorf("inspect fixture %s: %w", path, err)
	}
	if entry.Type()&os.ModeSymlink != 0 || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("fixture %s is a symbolic link; hostile fixtures must remain local data", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("fixture %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o111 != 0 {
		return fmt.Errorf("fixture %s is executable; hostile fixtures must remain data", path)
	}
	if info.Size() > maxScenarioFixtureBytes {
		return fmt.Errorf("fixture %s exceeds %d bytes", path, maxScenarioFixtureBytes)
	}
	return nil
}

func TestFixtureEntryValidationRejectsUnsafeFilesystemObjects(t *testing.T) {
	for _, test := range []struct {
		name      string
		prepare   func(string) error
		wantError string
	}{
		{name: "executable", prepare: func(path string) error { return os.WriteFile(path, []byte("inert"), 0o700) }, wantError: "is executable"},
		{name: "oversized", prepare: func(path string) error { return os.WriteFile(path, make([]byte, maxScenarioFixtureBytes+1), 0o600) }, wantError: "exceeds"},
		{name: "symlink", prepare: func(path string) error { return os.Symlink("outside", path) }, wantError: "symbolic link"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fixture")
			if err := test.prepare(path); err != nil {
				t.Fatal(err)
			}
			entry, err := os.ReadDir(filepath.Dir(path))
			if err != nil || len(entry) != 1 {
				t.Fatalf("read synthetic fixture: %v", err)
			}
			if err := validateFixtureEntry(path, entry[0]); err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("validation error = %v, want %q", err, test.wantError)
			}
		})
	}
}
