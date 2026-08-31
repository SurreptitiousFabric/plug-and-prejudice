package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestDecodeRejectsDuplicateMembersBeforeTypedDecode(t *testing.T) {
	valid, err := json.Marshal(validReport())
	if err != nil {
		t.Fatal(err)
	}
	duplicateTop := bytes.Replace(valid, []byte(`"status":"complete"`), []byte(`"status":"incomplete","status":"complete"`), 1)
	duplicateNested := bytes.Replace(valid, []byte(`"scannerVersion":"test"`), []byte(`"scannerVersion":"forged","scannerVersion":"test"`), 1)
	for _, data := range [][]byte{duplicateTop, duplicateNested} {
		if _, err := Decode(data); err == nil || !strings.Contains(err.Error(), "duplicate JSON object member") {
			t.Fatalf("duplicate member result = %v", err)
		}
	}
}

func TestDecodeRequiresExactSchemaMemberNames(t *testing.T) {
	valid, err := json.Marshal(validReport())
	if err != nil {
		t.Fatal(err)
	}
	tests := [][]byte{
		bytes.Replace(valid, []byte(`"schemaVersion":"2.0.0"`), []byte(`"schemaVersion":"1.0.0","SCHEMAVERSION":"2.0.0"`), 1),
		bytes.Replace(valid, []byte(`"status":"complete"`), []byte(`"status":"complete","STATUS":"incomplete"`), 1),
		bytes.Replace(valid, []byte(`"scannerVersion":"test"`), []byte(`"SCANNERVERSION":"test"`), 1),
	}
	for _, data := range tests {
		if _, err := Decode(data); err == nil || !strings.Contains(err.Error(), "incorrectly cased") {
			t.Fatalf("case alias result = %v", err)
		}
	}
	graph := graphReport(t)
	encoded, err := EncodeCanonical(graph)
	if err != nil {
		t.Fatal(err)
	}
	for _, replacement := range [][2]string{{`"claim":"fact"`, `"claim":"fact","CLAIM":"inference"`}, {`"evidenceSource":"target-source"`, `"evidenceSource":"target-source","EVIDENCESOURCE":"omarchy-audit"`}} {
		data := bytes.Replace(encoded, []byte(replacement[0]), []byte(replacement[1]), 1)
		if _, err := Decode(data); err == nil || !strings.Contains(err.Error(), "incorrectly cased") {
			t.Fatalf("nested alias result = %v", err)
		}
	}
}

func TestExactMemberPassAcceptsEverySchemaObjectAndDataMapKeys(t *testing.T) {
	values := []any{
		Report{}, ReviewSummary{}, ReviewReason{}, ImpactSummary{}, ConfidenceSummary{}, CoverageSummary{}, UnknownSummary{}, ClaimCounts{},
		ScanMetadata{ResourceLimits: &ResourceLimits{}}, ResourceLimits{}, Target{Manifest: &Manifest{Kinds: []string{}, EntryPoints: map[string]string{"ArBiTrArY-Key": "value"}}}, Manifest{Kinds: []string{}, EntryPoints: map[string]string{"STATUS": "data-key"}},
		File{Binary: &Binary{}, Archive: &Archive{}}, Binary{}, Archive{Entries: []ArchiveEntry{}}, ArchiveEntry{}, Operation{}, Resource{}, Finding{}, Unknown{}, ValueOrigin{}, Provenance{},
		Relationship{Comparison: &ComparisonBasis{}}, ComparisonBasis{}, Evidence{}, EvidenceInput{}, Limitation{}, ScanError{},
	}
	for _, value := range values {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateJSONStructure(data, reflect.TypeOf(value)); err != nil {
			t.Fatalf("%T exact fields rejected: %v\n%s", value, err, data)
		}
	}
}

func TestDecodeRejectsMalformedUnicodeWithoutRejectingReplacementCharacter(t *testing.T) {
	valid, err := json.Marshal(validReport())
	if err != nil {
		t.Fatal(err)
	}
	invalidRawValue := bytes.Replace(valid, []byte(`"example"`), []byte{'"', 0xff, '"'}, 1)
	invalidRawName := bytes.Replace(valid, []byte(`"status"`), []byte{'"', 's', 0xff, '"'}, 1)
	for _, fragment := range []string{`\ud800`, `\udc00`, `\ud800\u0041`} {
		data := bytes.Replace(valid, []byte(`"example"`), []byte(`"`+fragment+`"`), 1)
		if _, err := Decode(data); err == nil || !strings.Contains(err.Error(), "surrogate") {
			t.Fatalf("%s result = %v", fragment, err)
		}
	}
	for _, data := range [][]byte{invalidRawValue, invalidRawName} {
		if _, err := Decode(data); err == nil || !strings.Contains(err.Error(), "UTF-8") {
			t.Fatalf("invalid UTF-8 result = %v", err)
		}
	}
	for _, fragment := range []string{`\ud83d\ude00`, `�`} {
		data := bytes.Replace(valid, []byte(`"example"`), []byte(`"`+fragment+`"`), 1)
		if _, err := Decode(data); err != nil {
			t.Fatalf("valid Unicode %q rejected: %v", fragment, err)
		}
	}
}

func TestDecodeRejectsOversizedAndDeepInputBeforeReportAllocation(t *testing.T) {
	if _, err := Decode(make([]byte, MaxEncodedReportBytes+1)); err == nil || !strings.Contains(err.Error(), "encoded input exceeds") {
		t.Fatalf("oversized input result = %v", err)
	}
	deep := []byte(strings.Repeat("[", MaxJSONDepth+2) + "0" + strings.Repeat("]", MaxJSONDepth+2))
	if _, err := Decode(deep); err == nil || !strings.Contains(err.Error(), "nesting exceeds") {
		t.Fatalf("deep input result = %v", err)
	}
}

func TestEverySerializedStringAndMapKeyIsIndividuallyBounded(t *testing.T) {
	oversized := strings.Repeat("x", MaxHostileStringBytes)
	tests := []func(*Report){
		func(r *Report) { r.Scan.ScannerVersion = oversized },
		func(r *Report) {
			r.Target.Manifest = &Manifest{Kinds: []string{}, EntryPoints: map[string]string{oversized: "Panel.qml"}}
		},
		func(r *Report) {
			r.Limitations = []Limitation{{Code: oversized, Description: "bounded"}}
			r.Status = StatusIncomplete
		},
	}
	for _, mutate := range tests {
		r := validReport()
		mutate(&r)
		if r.Status == StatusIncomplete {
			_ = r.BuildReviewSummary(r.Review.AnalysisCoverage)
		}
		if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "encoded length") {
			t.Fatalf("oversized serialized string result = %v", err)
		}
	}
}

func TestCoverageIsRecomputedFromInventoryDispositions(t *testing.T) {
	r := validReport()
	r.Status = StatusIncomplete
	r.Target.FileCount = 1
	r.Target.ReadBytes = 1
	r.Inventory = []File{{Path: "plugin.sh", Kind: "regular", Mode: "-rw-r--r--", Size: 1, Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "text/plain", Analysis: AnalysisPartial, AnalysisReason: "dynamic behavior unresolved"}}
	refreshTestRootDigest(&r)
	r.Limitations = []Limitation{{Code: "dynamic", Description: "Dynamic behavior remains unresolved."}}
	forged := NewCoverageSummary(1, 0, 0)
	if err := r.BuildReviewSummary(forged); err == nil || !strings.Contains(err.Error(), "inventory dispositions") {
		t.Fatalf("forged coverage result = %v", err)
	}
	if err := r.BuildReviewSummary(NewCoverageSummary(0, 1, 0)); err != nil {
		t.Fatal(err)
	}
	r.Review.AnalysisCoverage = forged
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "inventory dispositions") {
		t.Fatalf("serialized forged coverage result = %v", err)
	}
}

func TestCompleteStatusRejectsIncompleteCoverage(t *testing.T) {
	r := validReport()
	r.Target.FileCount = 1
	r.Target.ReadBytes = 1
	r.Inventory = []File{{Path: "plugin.sh", Kind: "regular", Mode: "-rw-r--r--", Size: 1, Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "text/plain", Analysis: AnalysisPartial, AnalysisReason: "unsupported syntax"}}
	refreshTestRootDigest(&r)
	r.Review = nil
	if err := r.BuildReviewSummary(NewCoverageSummary(0, 1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "complete analysis coverage") {
		t.Fatalf("complete partial-coverage result = %v", err)
	}
}

func TestCoverageExclusionsAreVisibleAndCannotLaunderCompleteStatus(t *testing.T) {
	r := validReport()
	r.Inventory = []File{{Path: "plugin.sh", Kind: "regular", Mode: "-rw-r--r--", Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "text/plain", Analysis: AnalysisNotApplicable, AnalysisReason: "forged exclusion"}}
	r.Target.FileCount = 1
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		t.Fatal(err)
	}
	if got := r.Review.AnalysisCoverage; got.RetainedUnits != 1 || got.ExcludedUnits != 1 || got.TotalUnits != 0 {
		t.Fatalf("coverage accounting = %#v", got)
	}
	if err := r.Validate(); err == nil || (!strings.Contains(err.Error(), "supported artifact") && !strings.Contains(err.Error(), "exclude retained")) {
		t.Fatalf("source exclusion result = %v", err)
	}

	r = validReport()
	r.Inventory = make([]File, 1_000)
	for index := range r.Inventory {
		r.Inventory[index] = File{Path: fmt.Sprintf("asset-%04d.dat", index), Kind: "regular", Mode: "-rw-r--r--", Analysis: AnalysisNotApplicable, AnalysisReason: "opaque inert data asset"}
	}
	r.Target.FileCount = len(r.Inventory)
	refreshTestRootDigest(&r)
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		t.Fatal(err)
	}
	if r.Review.AnalysisCoverage.ExcludedUnits != 1_000 || r.Review.AnalysisCoverage.RetainedUnits != 1_000 {
		t.Fatalf("excluded inventory disappeared: %#v", r.Review.AnalysisCoverage)
	}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "cannot exclude retained") {
		t.Fatalf("mass exclusion result = %v", err)
	}
}

func TestNativeAndArchiveArtifactsCannotClaimCompleteSemanticAnalysis(t *testing.T) {
	elf := validReport()
	elf.Inventory = []File{{Path: "helper", Kind: "regular", Mode: "-rwxr-xr-x", Size: 1, Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "application/x-elf", Analysis: AnalysisAnalyzed, Binary: &Binary{Format: "ELF", Class: "ELFCLASS64", ByteOrder: "ELFDATA2LSB", Machine: "EM_X86_64", Type: "ET_DYN", Libraries: []string{}, ImportedSymbols: []string{}, ExtractedStrings: []string{}, EmbeddedURLs: []string{}, FileCapabilities: []string{}}}}
	elf.Target.FileCount, elf.Target.BinaryBytes = 1, 1
	_ = elf.BuildReviewSummary(coverageFromInventory(elf.Inventory))
	if err := elf.Validate(); err == nil || !strings.Contains(err.Error(), "ELF") {
		t.Fatalf("fully analyzed ELF result = %v", err)
	}
	archive := validReport()
	archive.Inventory = []File{{Path: "payload.zip", Kind: "regular", Mode: "-rw-r--r--", Size: 1, Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "application/zip", Analysis: AnalysisAnalyzed, Archive: &Archive{Format: "zip", Entries: []ArchiveEntry{}, InventoryComplete: true, RetainedUncompressedBytes: 0}}}
	archive.Target.FileCount, archive.Target.ReadBytes = 1, 1
	_ = archive.BuildReviewSummary(coverageFromInventory(archive.Inventory))
	if err := archive.Validate(); err == nil || !strings.Contains(err.Error(), "archive") {
		t.Fatalf("fully analyzed archive result = %v", err)
	}
}

func TestEvidenceMustBeAnchoredToDeclaredInput(t *testing.T) {
	r := validReport()
	r.Inventory = []File{{Path: "plugin.sh", Kind: "regular", Mode: "-rw-r--r--", Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "text/plain", Analysis: AnalysisAnalyzed}}
	r.Target.FileCount = 1
	r.Operations = []Operation{{ID: "op", Category: "execution", Command: "true", Scope: ScopeRuntime, Confidence: ConfidenceHigh, Evidence: Evidence{Path: "missing.sh"}, Provenance: testProvenance}}
	buildTestEvidence(t, &r)
	// Remove the helper-added path to exercise the accepting boundary directly.
	r.Inventory = r.Inventory[:1]
	r.Target.FileCount = 1
	refreshTestRootDigest(&r)
	_ = r.BuildReviewSummary(coverageFromInventory(r.Inventory))
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "absent from target inventory") {
		t.Fatalf("unanchored local path result = %v", err)
	}
	r.Operations[0].Evidence = Evidence{InputID: "undeclared", Path: "plugin.sh"}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "undeclared input") {
		t.Fatalf("undeclared input result = %v", err)
	}
	r.Operations[0].Evidence = Evidence{InputID: TargetEvidenceInputID, Path: "plugin.sh"}
	if err := r.Validate(); err != nil {
		t.Fatalf("valid target evidence rejected: %v", err)
	}
}

func TestUnknownCannotMasqueradeAsSeverityBearingFinding(t *testing.T) {
	r := validReport()
	r.Status = StatusIncomplete
	r.Findings = []Finding{{ID: "unknown-as-finding", Claim: ClaimType("unknown"), Severity: SeverityInformational, Confidence: ConfidenceHigh, Category: "coverage", Scope: ScopeUnknown, Title: "Unknown", Explanation: "Hidden as a finding.", Evidence: []Evidence{{Path: "plugin.sh"}}, Provenance: testProvenance}}
	r.Limitations = []Limitation{{Code: "coverage", Description: "Coverage incomplete."}}
	buildTestEvidence(t, &r)
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "invalid claim") {
		t.Fatalf("unknown finding result = %v", err)
	}
}

func TestInferenceRequiresDeclaredSupport(t *testing.T) {
	r := validReport()
	r.Findings = []Finding{{ID: "unsupported-inference", Claim: ClaimInference, Severity: SeverityHigh, Confidence: ConfidenceHigh, Category: "conclusion", Scope: ScopeRuntime, Title: "Unsupported", Explanation: "No supporting operation.", Evidence: []Evidence{{Path: "plugin.sh"}}, Provenance: testProvenance}}
	buildTestEvidence(t, &r)
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "no declared supporting operation") {
		t.Fatalf("unsupported inference result = %v", err)
	}
}

func TestLocalProvenanceMustMatchTrustedScannerIdentity(t *testing.T) {
	r := validReport()
	r.Operations = []Operation{{ID: "op", Category: "execution", Command: "true", Scope: ScopeRuntime, Confidence: ConfidenceHigh, Evidence: Evidence{Path: "plugin.sh"}, Provenance: testProvenance}}
	buildTestEvidence(t, &r)
	for _, mutate := range []func(*Provenance){
		func(p *Provenance) { p.Analyzer = "plugin-controlled/scanner" },
		func(p *Provenance) { p.AnalyzerVersion = "different-version" },
	} {
		bad := r
		bad.Operations = append([]Operation(nil), r.Operations...)
		mutate(&bad.Operations[0].Provenance)
		if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "trusted scanner identity") {
			t.Fatalf("forged provenance result = %v", err)
		}
	}
}

func TestDedicatedUnknownRejectsNullStructuredCollections(t *testing.T) {
	r := graphReport(t)
	for _, mutate := range []func(*Unknown){
		func(value *Unknown) { value.Origins = nil },
		func(value *Unknown) { value.AffectedOperations = nil },
		func(value *Unknown) { value.SuppressedRules = nil },
	} {
		bad := r
		bad.Unknowns = append([]Unknown(nil), r.Unknowns...)
		mutate(&bad.Unknowns[0])
		if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "must be JSON arrays") {
			t.Fatalf("null unknown collection result = %v", err)
		}
	}
}

func TestGraphAndJSONEncodingAreDeterministicAcrossRepeatedBuilds(t *testing.T) {
	r := graphReport(t)
	var first []byte
	for iteration := 0; iteration < 100; iteration++ {
		if err := r.BuildEvidenceGraph(); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if iteration == 0 {
			first = encoded
		} else if !bytes.Equal(first, encoded) {
			t.Fatalf("iteration %d produced different bytes", iteration)
		}
	}
}

func TestCanonicalEncodingIsIndependentOfNonsemanticInsertionOrder(t *testing.T) {
	base := graphReport(t)
	base.Inventory = append(base.Inventory, File{Path: "z.sh", Kind: "regular", Mode: "-rw-r--r--", Inspected: true, SHA256: strings.Repeat("b", 64), ContentType: "text/plain", Analysis: AnalysisAnalyzed})
	base.Target.FileCount = len(base.Inventory)
	refreshTestRootDigest(&base)
	base.Operations = append(base.Operations, Operation{ID: "operation-z", Category: "process-execution", Command: "wget", Scope: ScopeRuntime, Confidence: ConfidenceHigh, Evidence: Evidence{InputID: TargetEvidenceInputID, Path: "z.sh"}, Provenance: testProvenance})
	base.Resources = append(base.Resources, Resource{ID: "resource-z", Kind: "network-domain", Access: "connect", Value: "z.test", Scope: ScopeRuntime, Confidence: ConfidenceHigh, Evidence: Evidence{InputID: TargetEvidenceInputID, Path: "z.sh"}, RelatedOperationID: "operation-z", Provenance: testProvenance})
	base.Unknowns = append(base.Unknowns, Unknown{ID: "unknown-z", Category: "dynamic", Reason: UnknownDynamicValue, Scope: ScopeRuntime, Confidence: ConfidenceHigh, Title: "Z unresolved", Description: "Z remains dynamic.", Evidence: []Evidence{{InputID: TargetEvidenceInputID, Path: "z.sh"}}, Origins: []ValueOrigin{}, AffectedOperations: []string{"operation-z"}, SuppressedRules: []string{}, Provenance: testProvenance})
	base.Limitations = []Limitation{{Code: "z-limit", Description: "Z limitation.", Scope: ScopeUnknown}, {Code: "a-limit", Description: "A limitation.", Scope: ScopeRuntime}}
	base.Errors = []ScanError{{Code: "z-error", Message: "Z error."}, {Code: "a-error", Message: "A error."}}
	appendTestExternalInput(&base, "input-unused-z")
	for index := 0; index < 10; index++ {
		base.Findings = append(base.Findings, Finding{ID: fmt.Sprintf("finding-extra-%02d", index), Claim: ClaimFact, Severity: SeverityMedium, Confidence: ConfidenceHigh, Category: "test", Scope: ScopeRuntime, Title: fmt.Sprintf("Reason %02d", index), Explanation: "Deterministic reason ordering.", Evidence: []Evidence{{InputID: TargetEvidenceInputID, Path: "plugin.sh"}}, Related: []string{}, Provenance: testProvenance})
	}
	if err := base.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	if err := base.BuildReviewSummary(coverageFromInventory(base.Inventory)); err != nil {
		t.Fatal(err)
	}
	want, err := EncodeCanonical(base)
	if err != nil {
		t.Fatal(err)
	}
	random := rand.New(rand.NewSource(23))
	for iteration := 0; iteration < 100; iteration++ {
		candidate := base
		candidate.Inventory = append([]File(nil), base.Inventory...)
		candidate.Operations = append([]Operation(nil), base.Operations...)
		candidate.Resources = append([]Resource(nil), base.Resources...)
		candidate.Findings = append([]Finding(nil), base.Findings...)
		candidate.Unknowns = append([]Unknown(nil), base.Unknowns...)
		candidate.Relationships = append([]Relationship(nil), base.Relationships...)
		candidate.Limitations = append([]Limitation(nil), base.Limitations...)
		candidate.Errors = append([]ScanError(nil), base.Errors...)
		candidate.EvidenceInputs = append([]EvidenceInput(nil), base.EvidenceInputs...)
		random.Shuffle(len(candidate.Inventory), func(i, j int) {
			candidate.Inventory[i], candidate.Inventory[j] = candidate.Inventory[j], candidate.Inventory[i]
		})
		random.Shuffle(len(candidate.Operations), func(i, j int) {
			candidate.Operations[i], candidate.Operations[j] = candidate.Operations[j], candidate.Operations[i]
		})
		random.Shuffle(len(candidate.Resources), func(i, j int) {
			candidate.Resources[i], candidate.Resources[j] = candidate.Resources[j], candidate.Resources[i]
		})
		random.Shuffle(len(candidate.Findings), func(i, j int) {
			candidate.Findings[i], candidate.Findings[j] = candidate.Findings[j], candidate.Findings[i]
		})
		random.Shuffle(len(candidate.Unknowns), func(i, j int) {
			candidate.Unknowns[i], candidate.Unknowns[j] = candidate.Unknowns[j], candidate.Unknowns[i]
		})
		random.Shuffle(len(candidate.Relationships), func(i, j int) {
			candidate.Relationships[i], candidate.Relationships[j] = candidate.Relationships[j], candidate.Relationships[i]
		})
		random.Shuffle(len(candidate.Limitations), func(i, j int) {
			candidate.Limitations[i], candidate.Limitations[j] = candidate.Limitations[j], candidate.Limitations[i]
		})
		random.Shuffle(len(candidate.Errors), func(i, j int) { candidate.Errors[i], candidate.Errors[j] = candidate.Errors[j], candidate.Errors[i] })
		random.Shuffle(len(candidate.EvidenceInputs), func(i, j int) {
			candidate.EvidenceInputs[i], candidate.EvidenceInputs[j] = candidate.EvidenceInputs[j], candidate.EvidenceInputs[i]
		})
		got, err := EncodeCanonical(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("shuffle %d changed canonical bytes", iteration)
		}
	}
}

func TestBoundedCanonicalEncodingRejectsAggregateOverageWithoutPartialOutput(t *testing.T) {
	r := validReport()
	r.Inventory = []File{{Path: "plugin.sh", Kind: "regular", Mode: "-rw-r--r--", Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "text/plain", Analysis: AnalysisAnalyzed}}
	r.Target.FileCount = 1
	refreshTestRootDigest(&r)
	r.Operations = make([]Operation, 5_000)
	for index := range r.Operations {
		r.Operations[index] = Operation{ID: fmt.Sprintf("operation-%05d", index), Category: "bounded-output", Command: fmt.Sprintf("%05d-%s", index, strings.Repeat("x", 3_500)), Scope: ScopeRuntime, Confidence: ConfidenceHigh, Evidence: Evidence{Path: "plugin.sh"}, Provenance: testProvenance}
	}
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		t.Fatal(err)
	}
	var destination bytes.Buffer
	err := WriteCanonical(&destination, r)
	if !errors.Is(err, ErrEncodedReportTooLarge) {
		t.Fatalf("aggregate overage result = %v", err)
	}
	if destination.Len() != 0 {
		t.Fatalf("partial report escaped: %d bytes", destination.Len())
	}
}

func TestDocumentedRelationshipLimitsMatchContractConstants(t *testing.T) {
	if MaxEvidenceRelations != 680_000 || MaxProducedEvidenceRelations != 20_000 {
		t.Fatalf("relationship limits = accepting %d, producer %d", MaxEvidenceRelations, MaxProducedEvidenceRelations)
	}
	data, err := os.ReadFile("../../docs/report-contract.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "680,000") || !strings.Contains(text, "20,000-relationship budget") {
		t.Fatal("documented relationship ceilings drifted from contract constants")
	}
}
