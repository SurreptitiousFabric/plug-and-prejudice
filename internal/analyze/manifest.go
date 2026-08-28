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
	BarWidget     json.RawMessage   `json:"barWidget"`
}

func analyzeManifest(contents map[string][]byte, result *Result) {
	data, exists := contents["manifest.json"]
	if !exists {
		manifestFinding(result, report.SeverityMedium, "missing-manifest", "Plugin manifest is missing", "Current Omarchy Shell plugins require manifest.json at the repository root. Without it, the target cannot be validated or loaded through the documented plugin mechanism.")
		return
	}
	var document manifestDocument
	if err := json.Unmarshal(data, &document); err != nil {
		result.Limitations = append(result.Limitations, report.Limitation{Code: "manifest-parse-error", Description: err.Error(), Path: "manifest.json"})
		manifestFinding(result, report.SeverityMedium, "invalid-manifest-json", "Plugin manifest is not valid JSON", "The declared plugin identity, kinds, and entry points cannot be established because manifest.json could not be parsed.")
		return
	}
	document = retainManifestDocument(document, result)
	result.Manifest = &report.Manifest{
		ID: document.ID, Name: document.Name, Version: document.Version,
		Description: document.Description, Kinds: nonNilStrings(document.Kinds), EntryPoints: nonNilMap(document.EntryPoints),
	}
	problems := validateManifest(document, contents)
	for index, problem := range problems {
		manifestFinding(result, report.SeverityMedium, fmt.Sprintf("manifest-contract-%d", index+1), "Manifest does not satisfy the Omarchy plugin contract", problem)
	}
}

func retainManifestDocument(document manifestDocument, result *Result) manifestDocument {
	limited := false
	if len(document.Kinds) > report.MaxManifestKinds {
		document.Kinds = document.Kinds[:report.MaxManifestKinds]
		limited = true
	}
	if len(document.EntryPoints) > report.MaxManifestEntryPoints {
		keys := make([]string, 0, len(document.EntryPoints))
		for key := range document.EntryPoints {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		retained := make(map[string]string, report.MaxManifestEntryPoints)
		for _, key := range keys[:report.MaxManifestEntryPoints] {
			retained[key] = document.EntryPoints[key]
		}
		document.EntryPoints = retained
		limited = true
	}
	document.ID, limited = retainManifestString(document.ID, limited)
	document.Name, limited = retainManifestString(document.Name, limited)
	document.Version, limited = retainManifestString(document.Version, limited)
	document.Description, limited = retainManifestString(document.Description, limited)
	for index, value := range document.Kinds {
		document.Kinds[index], limited = retainManifestString(value, limited)
	}
	keys := make([]string, 0, len(document.EntryPoints))
	for key := range document.EntryPoints {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	boundedEntries := make(map[string]string, len(keys))
	for _, key := range keys {
		boundedKey, keyLimited := boundedEncodedString(key)
		boundedValue, valueLimited := boundedEncodedString(document.EntryPoints[key])
		if _, collision := boundedEntries[boundedKey]; collision {
			limited = true
			continue
		}
		boundedEntries[boundedKey] = boundedValue
		limited = limited || keyLimited || valueLimited
	}
	document.EntryPoints = boundedEntries
	if limited {
		addProductionLimitation(result, "manifest.json", "manifest collections")
	}
	return document
}

func retainManifestString(value string, alreadyLimited bool) (string, bool) {
	bounded, limited := boundedEncodedString(value)
	return bounded, alreadyLimited || limited
}

func boundedEncodedString(value string) (string, bool) {
	encoded, err := json.Marshal(value)
	if err == nil && len(encoded) <= report.MaxHostileStringBytes {
		return value, false
	}
	const marker = "...[truncated]"
	markerEncoded, _ := json.Marshal(marker)
	budget := report.MaxHostileStringBytes - 2 - (len(markerEncoded) - 2)
	var output strings.Builder
	used := 0
	for _, valueRune := range value {
		piece := string(valueRune)
		pieceEncoded, _ := json.Marshal(piece)
		cost := len(pieceEncoded) - 2
		if cost > budget-used {
			break
		}
		output.WriteString(piece)
		used += cost
	}
	output.WriteString(marker)
	return output.String(), true
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
	for key, entry := range document.EntryPoints {
		if !safeEntryPoint(entry) {
			problems = append(problems, fmt.Sprintf("entryPoints.%s value %q must be a safe relative path without '..'.", key, entry))
			continue
		}
		if _, exists := contents[path.Clean(entry)]; !exists {
			problems = append(problems, fmt.Sprintf("entryPoints.%s file %q is absent or was not inspectable.", key, entry))
		}
	}
	if len(document.BarWidget) > 0 {
		var metadata map[string]json.RawMessage
		if json.Unmarshal(document.BarWidget, &metadata) == nil && metadata != nil {
			if raw, exists := metadata["defaultSection"]; exists {
				var section string
				if json.Unmarshal(raw, &section) != nil || (section != "left" && section != "center" && section != "right") {
					problems = append(problems, "barWidget.defaultSection must be left, center, or right when present.")
				}
			}
		}
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
			continue
		}
	}
	sort.Strings(problems)
	return problems
}

func safeEntryPoint(value string) bool {
	return value != "" && !strings.ContainsAny(value, "\r\n") && !strings.HasPrefix(value, "/") && !strings.Contains(value, "..") && path.Clean(value) == value
}

func manifestFinding(result *Result, severity report.Severity, suffix, title, explanation string) {
	appendFinding(result, report.Finding{
		ID: "finding-" + suffix, Claim: report.ClaimFact, Severity: severity,
		Confidence: report.ConfidenceHigh, Category: "manifest", Title: title, Explanation: explanation,
		Evidence: []report.Evidence{{Path: "manifest.json"}}, Provenance: sourceProvenance("manifest-contract/v1"),
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
