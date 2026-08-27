package analyze

import "testing"

func TestValidManifestProducesMetadataWithoutManifestFinding(t *testing.T) {
	result := Sources(withValidManifest(map[string][]byte{}))
	if result.Manifest == nil || result.Manifest.ID != "example.test" || result.Manifest.EntryPoints["panel"] != "Panel.qml" {
		t.Fatalf("manifest metadata not preserved: %#v", result.Manifest)
	}
	if hasFindingCategory(result, "manifest") {
		t.Fatalf("valid manifest produced finding: %#v", result.Findings)
	}
}

func TestMissingManifestIsReportedAsFact(t *testing.T) {
	result := Sources(map[string][]byte{"Panel.qml": []byte("Item {}\n")})
	if !hasFindingID(result, "finding-missing-manifest") {
		t.Fatalf("missing manifest was not reported: %#v", result.Findings)
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

func TestMalformedManifestAddsFindingAndCompletenessLimitation(t *testing.T) {
	result := Sources(map[string][]byte{"manifest.json": []byte("{")})
	if !hasFindingID(result, "finding-invalid-manifest-json") {
		t.Fatalf("malformed manifest finding missing: %#v", result.Findings)
	}
	if len(result.Limitations) != 1 || result.Limitations[0].Code != "manifest-parse-error" {
		t.Fatalf("malformed manifest limitation missing: %#v", result.Limitations)
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
