package analyze

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestValidManifestProducesMetadataWithoutManifestFinding(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{}))
	if result.Manifest == nil || result.Manifest.ID != "example.test" || result.Manifest.EntryPoints["panel"] != "Panel.qml" {
		t.Fatalf("manifest metadata not preserved: %#v", result.Manifest)
	}
	if hasFindingCategory(result, "manifest") {
		t.Fatalf("valid manifest produced finding: %#v", result.Findings)
	}
}

func TestMissingManifestIsReportedAsUnanchoredTargetLimitation(t *testing.T) {
	result := Sources(map[string][]byte{"Panel.qml": []byte("Item {}\n")})
	if len(result.Limitations) == 0 || result.Limitations[0].Code != "missing-manifest" {
		t.Fatalf("missing manifest limitation was not reported: %#v", result.Limitations)
	}
}

func TestManifestRejectsReservedIDAndEscapingEntryPoint(t *testing.T) {
	result := Sources(map[string][]byte{
		"manifest.json": []byte(`{"schemaVersion":1,"id":"omarchy.lookalike","name":"Test","version":"1","kinds":["service"],"entryPoints":{"service":"../Service.qml"}}`),
	})
	if countFindingCategory(result, "manifest") != 2 {
		t.Fatalf("contract problems were not independently reported: %#v", result.Findings)
	}
}

func TestManifestValidatesEveryEntryPointAndBarWidgetSection(t *testing.T) {
	result := Sources(map[string][]byte{
		"manifest.json": []byte(`{"schemaVersion":1,"id":"example.test","name":"Test","version":"1","kinds":["panel"],"entryPoints":{"panel":"Panel.qml","unused":"../outside.qml"},"barWidget":{"defaultSection":"bottom"}}`),
		"Panel.qml":     []byte("Item {}\n"),
	})
	if countFindingCategory(result, "manifest") != 2 {
		t.Fatalf("all-entry-point/default-section validation = %#v", result.Findings)
	}
}

func TestManifestRejectsMissingAndNewlineAdditionalEntryPoints(t *testing.T) {
	result := Sources(map[string][]byte{
		"manifest.json": []byte("{\"schemaVersion\":1,\"id\":\"example.test\",\"name\":\"Test\",\"version\":\"1\",\"kinds\":[\"panel\"],\"entryPoints\":{\"panel\":\"Panel.qml\",\"missing\":\"missing.qml\",\"newline\":\"bad\\nname.qml\"}}"),
		"Panel.qml":     []byte("Item {}\n"),
	})
	if countFindingCategory(result, "manifest") != 2 {
		t.Fatalf("additional entry-point contract problems = %#v", result.Findings)
	}
}

func TestManifestAcceptsDocumentedBarWidgetSections(t *testing.T) {
	for _, section := range []string{"left", "center", "right"} {
		result := Sources(map[string][]byte{
			"manifest.json": []byte(`{"schemaVersion":1,"id":"example.test","name":"Test","version":"1","kinds":["bar-widget"],"entryPoints":{"barWidget":"Widget.qml"},"barWidget":{"defaultSection":"` + section + `"}}`),
			"Widget.qml":    []byte("Item {}\n"),
		})
		if hasFindingCategory(result, "manifest") {
			t.Errorf("documented section %q was rejected: %#v", section, result.Findings)
		}
	}
}

func TestMalformedManifestAddsFindingAndCompletenessLimitation(t *testing.T) {
	result := Sources(map[string][]byte{"manifest.json": []byte("{")})
	if !hasFindingID(result, "finding-invalid-manifest-json") {
		t.Fatalf("malformed manifest finding missing: %#v", result.Findings)
	}
	if len(result.Limitations) != 1 || result.Limitations[0].Code != "manifest-parse-error" {
		t.Fatalf("malformed manifest limitation missing: %#v", result.Limitations)
	}
}

func TestManifestStringsAreBoundedByJSONEncodedSize(t *testing.T) {
	result := Sources(map[string][]byte{"manifest.json": []byte(`{"schemaVersion":1,"id":"example.test","name":"` + strings.Repeat(`\u0001`, report.MaxHostileStringBytes) + `","version":"1","kinds":["panel"],"entryPoints":{"panel":"Panel.qml"}}`), "Panel.qml": []byte("Item {}")})
	if result.Manifest == nil || !hasLimitationCode(result, "result-production-limit") {
		t.Fatalf("bounded manifest = %#v, limitations %#v", result.Manifest, result.Limitations)
	}
	encoded, err := json.Marshal(result.Manifest.Name)
	if err != nil || len(encoded) > report.MaxHostileStringBytes {
		t.Fatalf("encoded manifest name = %d, %v", len(encoded), err)
	}
}

func hasFindingCategory(result Result, category string) bool {
	return countFindingCategory(result, category) > 0
}

func countFindingCategory(result Result, category string) int {
	count := 0
	for _, finding := range result.Findings {
		if finding.Category == category {
			count++
		}
	}
	return count
}

func hasFindingID(result Result, id string) bool {
	for _, finding := range result.Findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}
