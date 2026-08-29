package analyze

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

var manifestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type manifestDocument struct {
	SchemaVersion int               `json:"schemaVersion"`
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Version       string            `json:"version"`
	Description   string            `json:"description"`
	Kinds         []string          `json:"kinds"`
	EntryPoints   map[string]string `json:"entryPoints"`
}

func analyzeManifest(contents map[string][]byte, result *Result) {
	data, exists := contents["manifest.json"]
	if !exists {
		result.Limitations = append(result.Limitations, report.Limitation{Code: "missing-manifest", Description: "Current Omarchy Shell plugins require manifest.json at the repository root. Its absence cannot be anchored as file evidence, so it is retained as an explicit target-level limitation.", Scope: report.ScopeRuntime})
		return
	}
	var document manifestDocument
	if err := json.Unmarshal(data, &document); err != nil {
		result.Limitations = append(result.Limitations, report.Limitation{Code: "manifest-parse-error", Description: err.Error(), Path: "manifest.json"})
		manifestFinding(result, report.SeverityMedium, "invalid-manifest-json", "Plugin manifest is not valid JSON", "The declared plugin identity, kinds, and entry points cannot be established because manifest.json could not be parsed.")
		return
	}
	result.Manifest = &report.Manifest{
		ID: document.ID, Name: document.Name, Version: document.Version,
		Description: document.Description, Kinds: nonNilStrings(document.Kinds), EntryPoints: nonNilMap(document.EntryPoints),
	}
	problems := validateManifest(document, contents)
	for index, problem := range problems {
		manifestFinding(result, report.SeverityMedium, fmt.Sprintf("manifest-contract-%d", index+1), "Manifest does not satisfy the Omarchy plugin contract", problem)
	}
}

func validateManifest(document manifestDocument, contents map[string][]byte) []string {
	var problems []string
	if document.SchemaVersion != 1 {
		problems = append(problems, "schemaVersion must be the JSON number 1.")
	}
	if !manifestIDPattern.MatchString(document.ID) || strings.Contains(document.ID, "..") || strings.HasPrefix(document.ID, "omarchy.") {
		problems = append(problems, "id is empty, malformed, contains '..', or uses the reserved omarchy.* namespace.")
	}
	if document.Name == "" || document.Version == "" {
		problems = append(problems, "name and version are required non-empty manifest fields.")
	}
	if len(document.Kinds) == 0 {
		problems = append(problems, "kinds must be a non-empty array.")
	}
	required := map[string]string{"bar": "bar", "bar-widget": "barWidget", "menu": "menu", "overlay": "overlay", "panel": "panel", "service": "service"}
	for _, kind := range document.Kinds {
		entryKey, known := required[kind]
		if !known {
			continue
		}
		entry, ok := document.EntryPoints[entryKey]
		if !ok {
			problems = append(problems, fmt.Sprintf("kind %q requires entryPoints.%s.", kind, entryKey))
			continue
		}
		if !safeEntryPoint(entry) {
			problems = append(problems, fmt.Sprintf("entry point %q must be a safe relative path without '..'.", entry))
			continue
		}
		if _, exists := contents[path.Clean(entry)]; !exists {
			problems = append(problems, fmt.Sprintf("declared entry point %q is absent or was not inspectable.", entry))
		}
	}
	sort.Strings(problems)
	return problems
}

func safeEntryPoint(value string) bool {
	return value != "" && !strings.HasPrefix(value, "/") && !strings.Contains(value, "..") && path.Clean(value) == value
}

func manifestFinding(result *Result, severity report.Severity, suffix, title, explanation string) {
	result.Findings = append(result.Findings, report.Finding{
		ID: "finding-" + suffix, Claim: report.ClaimFact, Severity: severity,
		Confidence: report.ConfidenceHigh, Category: "manifest", Title: title, Explanation: explanation,
		Evidence: []report.Evidence{{Path: "manifest.json"}}, Provenance: sourceProvenance("manifest/v1"),
	})
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func nonNilMap(values map[string]string) map[string]string {
	if values == nil {
		return map[string]string{}
	}
	return values
}
