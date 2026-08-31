package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

var testProvenance = Provenance{RuleID: "test/v1", Analyzer: DeterministicAnalyzer, AnalyzerVersion: "test", EvidenceSource: EvidenceSourceTargetSource}

func appendTestExternalInput(r *Report, id string) Provenance {
	rawProvenance := Provenance{RuleID: OmarchyAuditObservationRule, Analyzer: OmarchyAuditAnalyzer, AnalyzerVersion: OmarchyAuditInputVersion, EvidenceSource: EvidenceSourceOmarchyAudit}
	bindingProvenance := Provenance{RuleID: ExternalBindingAssessmentRule, Analyzer: DeterministicAnalyzer, AnalyzerVersion: r.Scan.ScannerVersion, EvidenceSource: EvidenceSourceOmarchyAudit}
	r.EvidenceInputs = append(r.EvidenceInputs, NewOmarchyAuditEvidenceInput(id, "pinned test Omarchy audit", []byte(`{"commands":["curl"]}`)))
	r.Status = StatusIncomplete
	r.Unknowns = append(r.Unknowns, Unknown{ID: "unknown-binding-" + id, Category: ExternalEvidenceBindingCategory, Reason: UnknownExternalBinding, Scope: ScopeUnknown, Confidence: ConfidenceHigh, Title: "External input is not digest bound", Description: "Test input has no independently checked digest.", Evidence: []Evidence{{InputID: id, Path: "omarchy-audit.json"}}, Origins: []ValueOrigin{}, AffectedOperations: []string{}, SuppressedRules: []string{ExternalSnapshotBindingRule}, Provenance: bindingProvenance})
	return rawProvenance
}

func buildTestEvidence(t *testing.T, r *Report) {
	t.Helper()
	for index := range r.Operations {
		if r.Operations[index].Provenance.RuleID == "" {
			r.Operations[index].Provenance = testProvenance
		}
	}
	for index := range r.Resources {
		if r.Resources[index].Provenance.RuleID == "" {
			r.Resources[index].Provenance = testProvenance
		}
	}
	for index := range r.Findings {
		if r.Findings[index].Provenance.RuleID == "" {
			r.Findings[index].Provenance = testProvenance
		}
	}
	paths := map[string]bool{}
	for _, file := range r.Inventory {
		paths[file.Path] = true
	}
	add := func(e Evidence) {
		if e.Path != "" && !paths[e.Path] && !strings.HasPrefix(e.Path, "../") {
			r.Inventory = append(r.Inventory, File{Path: e.Path, Kind: "regular", Mode: "-rw-r--r--", Size: 0, Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "text/plain", Analysis: AnalysisAnalyzed})
			paths[e.Path] = true
		}
	}
	for _, item := range r.Operations {
		add(item.Evidence)
	}
	for _, item := range r.Resources {
		add(item.Evidence)
	}
	for _, item := range r.Findings {
		for _, evidence := range item.Evidence {
			add(evidence)
		}
	}
	for _, item := range r.Unknowns {
		for _, evidence := range item.Evidence {
			add(evidence)
		}
		for _, origin := range item.Origins {
			add(origin.Evidence)
		}
	}
	r.Target.FileCount = len(r.Inventory)
	refreshTestRootDigest(r)
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		t.Fatal(err)
	}
}

func TestVersionTwoGoldenReport(t *testing.T) {
	data, err := os.ReadFile("testdata/report-v2.0.0.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatalf("decode version-two fixture: %v", err)
	}
	if got.SchemaVersion != SchemaVersion {
		t.Fatalf("schema version = %q, want %q", got.SchemaVersion, SchemaVersion)
	}
	if len(got.Operations) != 1 || len(got.Resources) != 1 || len(got.Findings) != 2 || len(got.Unknowns) != 1 {
		t.Fatalf("fixture sections were not preserved: %#v", got)
	}
}

func validReport() Report {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	r := Report{
		SchemaVersion: SchemaVersion,
		Status:        StatusComplete,
		Scan: ScanMetadata{ScannerVersion: "test", PolicyVersion: "test", StartedAt: now, CompletedAt: now, Sandboxed: true,
			ResourceLimits: &ResourceLimits{MemoryMaxBytes: 256 << 20, TasksMax: 64, CPUQuotaPercent: 100, WallTimeSeconds: 30}},
		Target:         Target{DisplayName: "example"},
		EvidenceInputs: []EvidenceInput{{ID: TargetEvidenceInputID, Type: EvidenceInputTarget, Label: "test target", Format: TargetEvidenceInputFormat, Version: TargetEvidenceInputVersion}},
		Inventory:      []File{}, Operations: []Operation{}, Resources: []Resource{}, Findings: []Finding{}, Unknowns: []Unknown{}, Relationships: []Relationship{}, Limitations: []Limitation{}, Errors: []ScanError{},
	}
	refreshTestRootDigest(&r)
	if err := r.BuildReviewSummary(NewCoverageSummary(0, 0, 0)); err != nil {
		panic(err)
	}
	return r
}

func refreshTestRootDigest(r *Report) {
	digest, err := InventoryRootDigest(r.Inventory)
	if err != nil {
		panic(err)
	}
	r.Target.RootDigest = digest
	for index := range r.EvidenceInputs {
		if r.EvidenceInputs[index].ID == TargetEvidenceInputID {
			r.EvidenceInputs[index].SubjectRootDigest = digest
		}
	}
}

func finalizeNativeArtifactReport(r *Report) {
	r.Status = StatusIncomplete
	r.Unknowns = []Unknown{}
	for index := range r.Inventory {
		if r.Inventory[index].ContentType != "application/x-elf" {
			continue
		}
		r.Inventory[index].Analysis, r.Inventory[index].AnalysisReason = AnalysisPartial, "bounded ELF metadata cannot establish native behavior"
		evidence := Evidence{Path: r.Inventory[index].Path}
		r.Unknowns = append(r.Unknowns, Unknown{ID: fmt.Sprintf("unknown-native-test-%d", index), Category: "native-behavior", Reason: UnknownNativeBehavior, Scope: ScopeRuntime, Confidence: ConfidenceHigh, Title: "Native behavior unresolved", Description: "Metadata inspection is not complete native semantic analysis.", Evidence: []Evidence{evidence}, Origins: []ValueOrigin{}, AffectedOperations: []string{}, SuppressedRules: []string{}, Provenance: testProvenance})
	}
	if err := r.BuildEvidenceGraph(); err != nil {
		panic(err)
	}
	refreshTestRootDigest(r)
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		panic(err)
	}
}

func finalizeArchiveArtifactReport(r *Report) {
	r.Status = StatusIncomplete
	r.Inventory[0].Analysis, r.Inventory[0].AnalysisReason = AnalysisPartial, "bounded archive inventory is not semantic payload analysis"
	r.Limitations = []Limitation{{Code: "archive-semantic-analysis-unavailable", Description: "Archive contents were inventoried but not semantically analyzed.", Path: r.Inventory[0].Path, Scope: ScopeUnknown}}
	refreshTestRootDigest(r)
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		panic(err)
	}
}

func TestDecodeAcceptsValidReport(t *testing.T) {
	data, err := json.Marshal(validReport())
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(data)
	if err != nil || got.SchemaVersion != SchemaVersion {
		t.Fatalf("Decode() = %#v, %v", got, err)
	}
}

func TestDecodeRejectsUnknownFieldAndTrailingValue(t *testing.T) {
	data, _ := json.Marshal(validReport())
	withUnknown := strings.Replace(string(data), `"status":`, `"surprise":true,"status":`, 1)
	if _, err := Decode([]byte(withUnknown)); err == nil {
		t.Fatal("unknown report field was accepted")
	}
	if _, err := Decode(append(data, []byte(" {}​")...)); err == nil {
		t.Fatal("trailing JSON value was accepted")
	}
}

func TestValidateRejectsBrokenRelationshipsAndUnsafeEvidence(t *testing.T) {
	r := validReport()
	r.Status = StatusIncomplete
	r.Findings = []Finding{{
		ID: "finding-1", Claim: ClaimFact, Severity: SeverityHigh, Confidence: ConfidenceHigh,
		Category: "execution", Scope: ScopeRuntime, Title: "Example", Explanation: "Example", Provenance: testProvenance,
		Evidence: []Evidence{{Path: "../outside", LineStart: 1}}, Related: []string{"missing"},
	}}
	buildTestEvidence(t, &r)
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "unsafe target-relative path") {
		t.Fatalf("Validate() error = %v", err)
	}
	r.Findings[0].Evidence[0].Path = "plugin.sh"
	r.Inventory = []File{{Path: "plugin.sh", Kind: "regular", Mode: "-rw-r--r--", Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "text/plain", Analysis: AnalysisAnalyzed}}
	r.Target.FileCount = 1
	refreshTestRootDigest(&r)
	_ = r.BuildReviewSummary(coverageFromInventory(r.Inventory))
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "missing operation") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsDuplicateIdentitiesAndMissingEvidence(t *testing.T) {
	r := validReport()
	r.Status = StatusIncomplete
	r.Operations = []Operation{{
		ID: "operation-1", Category: "process-execution", Command: "example", Scope: ScopeRuntime, Confidence: ConfidenceHigh,
		Evidence: Evidence{Path: "plugin.sh", LineStart: 1},
	}}
	r.Resources = []Resource{{
		ID: "resource-1", Kind: "filesystem-path", Access: "read", Value: "/tmp/example", Scope: ScopeRuntime, Confidence: ConfidenceHigh,
		Evidence: Evidence{Path: "plugin.sh", LineStart: 1}, RelatedOperationID: "operation-1",
	}}
	r.Findings = []Finding{{
		ID: "finding-1", Claim: ClaimFact, Severity: SeverityLow, Confidence: ConfidenceHigh, Category: "example", Scope: ScopeRuntime,
		Title: "Example", Explanation: "Example", Evidence: []Evidence{{Path: "plugin.sh", LineStart: 1}}, Provenance: testProvenance,
	}}
	buildTestEvidence(t, &r)

	r.Resources = append(r.Resources, r.Resources[0])
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate resource ID") {
		t.Fatalf("duplicate resource error = %v", err)
	}
	r.Resources = r.Resources[:1]
	r.Findings = append(r.Findings, r.Findings[0])
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate finding ID") {
		t.Fatalf("duplicate finding error = %v", err)
	}
	r.Findings = r.Findings[:1]
	r.Findings[0].Evidence = nil
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "has no evidence") {
		t.Fatalf("missing finding evidence error = %v", err)
	}
	r.Findings[0].Evidence = []Evidence{{Path: "plugin.sh", LineStart: 1}}
	r.Resources[0].RelatedOperationID = ""
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "has no originating operation") {
		t.Fatalf("missing resource operation error = %v", err)
	}
}

func TestValidateRejectsInvalidInventoryLimitationsAndErrors(t *testing.T) {
	r := validReport()
	r.Status = StatusIncomplete
	r.Target.FileCount = 1
	r.Inventory = []File{{Path: "../outside", Kind: "regular", Mode: "-rw-r--r--", Size: 1}}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "unsafe target-relative path") {
		t.Fatalf("unsafe inventory path error = %v", err)
	}
	r.Inventory[0].Path = "plugin.sh"
	r.Inventory[0].Analysis = AnalysisUnanalyzed
	r.Inventory[0].AnalysisReason = "test input was not inspected"
	r.Inventory = append(r.Inventory, r.Inventory[0])
	r.Target.FileCount = 2
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate inventory path") {
		t.Fatalf("duplicate inventory path error = %v", err)
	}
	r.Inventory = r.Inventory[:1]
	r.Target.FileCount = 1
	refreshTestRootDigest(&r)
	r.Limitations = []Limitation{{Code: "unknown", Description: "Unknown", Path: "/host/path"}}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "unsafe target-relative path") {
		t.Fatalf("unsafe limitation path error = %v", err)
	}
	r.Limitations = []Limitation{}
	r.Errors = []ScanError{{Code: "read", Message: "failed", Path: "../outside"}}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "unsafe target-relative path") {
		t.Fatalf("unsafe error path error = %v", err)
	}
}

func TestValidateRequiresCanonicalAndRecomputedRootDigest(t *testing.T) {
	for _, digest := range []string{"short", strings.Repeat("g", 64), strings.Repeat("A", 64), strings.Repeat("0", 62)} {
		r := validReport()
		r.Target.RootDigest = digest
		if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "root digest") {
			t.Errorf("invalid digest %q result = %v", digest, err)
		}
	}
	r := validReport()
	r.Target.RootDigest = strings.Repeat("a", 64)
	r.EvidenceInputs[0].SubjectRootDigest = r.Target.RootDigest
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("forged canonical root digest result = %v", err)
	}
}

func TestValidateRejectsNoncanonicalEvidencePaths(t *testing.T) {
	for _, unsafe := range []string{"dir/../plugin.sh", "./plugin.sh", "dir//plugin.sh", `dir\plugin.sh`} {
		r := validReport()
		r.Status = StatusIncomplete
		r.Operations = []Operation{{
			ID: "operation-1", Category: "process-execution", Command: "example", Scope: ScopeRuntime, Confidence: ConfidenceHigh,
			Evidence: Evidence{Path: unsafe, LineStart: 1},
		}}
		if err := r.Validate(); err == nil {
			t.Errorf("noncanonical path %q was accepted", unsafe)
		}
	}
}

func TestValidateRejectsOversizedCollectionsBeforeEntries(t *testing.T) {
	tests := []struct {
		name string
		set  func(*Report)
	}{
		{"inventory", func(r *Report) { r.Inventory = make([]File, MaxInventoryEntries+1) }},
		{"operations", func(r *Report) { r.Operations = make([]Operation, MaxOperationEntries+1) }},
		{"resources", func(r *Report) { r.Resources = make([]Resource, MaxResourceEntries+1) }},
		{"findings", func(r *Report) { r.Findings = make([]Finding, MaxFindingEntries+1) }},
		{"unknowns", func(r *Report) { r.Unknowns = make([]Unknown, MaxUnknownEntries+1) }},
		{"relationships", func(r *Report) { r.Relationships = make([]Relationship, MaxEvidenceRelations+1) }},
		{"limitations", func(r *Report) { r.Limitations = make([]Limitation, MaxLimitationEntries+1) }},
		{"errors", func(r *Report) { r.Errors = make([]ScanError, MaxErrorEntries+1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := validReport()
			test.set(&r)
			err := r.Validate()
			if err == nil || !strings.Contains(err.Error(), "report "+test.name+" count") {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestCollectionBoundsAcceptExactLimits(t *testing.T) {
	r := Report{
		Inventory:     make([]File, MaxInventoryEntries),
		Operations:    make([]Operation, MaxOperationEntries),
		Resources:     make([]Resource, MaxResourceEntries),
		Findings:      make([]Finding, MaxFindingEntries),
		Unknowns:      make([]Unknown, MaxUnknownEntries),
		Relationships: make([]Relationship, MaxEvidenceRelations),
		Limitations:   make([]Limitation, MaxLimitationEntries),
		Errors:        make([]ScanError, MaxErrorEntries),
	}
	if err := validateCollectionBounds(r); err != nil {
		t.Fatalf("exact collection limits were rejected: %v", err)
	}
}

func TestValidateRejectsOversizedNestedCollections(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Report)
	}{
		{"manifest-kinds", func(r *Report) {
			r.Target.Manifest = &Manifest{Kinds: make([]string, MaxManifestKinds+1), EntryPoints: map[string]string{}}
		}},
		{"manifest-entry-points", func(r *Report) {
			entries := make(map[string]string, MaxManifestEntryPoints+1)
			for i := 0; i <= MaxManifestEntryPoints; i++ {
				entries[fmt.Sprint(i)] = "x"
			}
			r.Target.Manifest = &Manifest{Kinds: []string{}, EntryPoints: entries}
		}},
		{"operation-arguments", func(r *Report) {
			r.Operations = []Operation{{ID: "op", Category: "language-call", Command: "call", Arguments: make([]string, MaxOperationArguments+1)}}
		}},
		{"finding-evidence", func(r *Report) {
			r.Findings = []Finding{{ID: "finding", Category: "test", Title: "test", Explanation: "test", Provenance: testProvenance, Evidence: make([]Evidence, MaxFindingEvidence+1)}}
		}},
		{"finding-related", func(r *Report) {
			r.Findings = []Finding{{ID: "finding", Category: "test", Title: "test", Explanation: "test", Provenance: testProvenance, Evidence: []Evidence{{Path: "x"}}, Related: make([]string, MaxFindingRelated+1)}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := validReport()
			test.mutate(&r)
			if err := r.Validate(); err == nil {
				t.Fatal("oversized nested collection was accepted")
			}
		})
	}
}

func TestValidateMeasuresHostileStringsAfterJSONEscaping(t *testing.T) {
	r := validReport()
	// Each control byte expands to six JSON bytes; the raw input is well below
	// the encoded limit but its serialized form is not.
	r.Target.DisplayName = strings.Repeat("\x01", MaxHostileStringBytes/2)
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "encoded length") {
		t.Fatalf("escape-amplified string error = %v", err)
	}
}

func TestCompleteReportCannotHideLimitations(t *testing.T) {
	r := validReport()
	r.Limitations = []Limitation{{Code: "unknown", Description: "Not inspected"}}
	if err := r.Validate(); err == nil {
		t.Fatal("complete report with limitation was accepted")
	}
}

func TestNoncompleteReportMustExplainItsStatus(t *testing.T) {
	for _, status := range []Status{StatusIncomplete, StatusError} {
		r := validReport()
		r.Status = status
		if err := r.Validate(); err == nil {
			t.Errorf("unexplained %q report was accepted", status)
		}
	}

	r := validReport()
	r.Status = StatusIncomplete
	r.Limitations = []Limitation{{Code: "partial", Description: "Some input was not inspected"}}
	if err := r.BuildReviewSummary(r.Review.AnalysisCoverage); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("explained incomplete report was rejected: %v", err)
	}
	r.Status = StatusError
	r.Limitations = []Limitation{}
	r.Errors = []ScanError{{Code: "failed", Message: "Scan failed"}}
	if err := r.BuildReviewSummary(r.Review.AnalysisCoverage); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("explained error report was rejected: %v", err)
	}
}

func TestDedicatedUnknownValidatesAndExplainsIncompleteStatus(t *testing.T) {
	r := validReport()
	evidence := Evidence{Path: "plugin.sh", LineStart: 2, LineEnd: 2, Operation: "$helper --check", Excerpt: "$helper --check"}
	r.Status = StatusIncomplete
	r.Operations = []Operation{{ID: "op-dynamic", Category: "process-execution", Command: "<dynamic>", Dynamic: true, Scope: ScopeRuntime, Confidence: ConfidenceMedium, Evidence: evidence, Provenance: testProvenance}}
	r.Unknowns = []Unknown{{ID: "unknown-helper", Category: "unresolved-command", Reason: UnknownDynamicValue, Scope: ScopeRuntime, Confidence: ConfidenceHigh,
		Title: "Executable unresolved", Description: "The helper is selected at runtime.", Evidence: []Evidence{evidence},
		Origins: []ValueOrigin{{Kind: OriginParameterExpansion, Name: "helper", Evidence: evidence}}, AffectedOperations: []string{"op-dynamic"},
		SuppressedRules: []string{"command-capability/v1"}, Provenance: testProvenance}}
	buildTestEvidence(t, &r)
	if err := r.Validate(); err != nil {
		t.Fatalf("traceable dedicated unknown was rejected: %v", err)
	}

	t.Run("invalid reason", func(t *testing.T) {
		bad := r
		bad.Unknowns = append([]Unknown(nil), r.Unknowns...)
		bad.Unknowns[0].Reason = UnknownReason("guessed")
		if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "invalid reason") {
			t.Fatalf("invalid unknown reason error = %v", err)
		}
	})
	t.Run("invalid origin kind", func(t *testing.T) {
		bad := r
		bad.Unknowns = append([]Unknown(nil), r.Unknowns...)
		bad.Unknowns[0].Origins = append([]ValueOrigin(nil), r.Unknowns[0].Origins...)
		bad.Unknowns[0].Origins[0].Kind = OriginKind("runtime-guess")
		if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "invalid origin kind") {
			t.Fatalf("invalid unknown origin error = %v", err)
		}
	})
	t.Run("missing affected operation", func(t *testing.T) {
		bad := r
		bad.Unknowns = append([]Unknown(nil), r.Unknowns...)
		bad.Unknowns[0].AffectedOperations = []string{"missing"}
		if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "missing operation") {
			t.Fatalf("missing affected operation error = %v", err)
		}
	})
	t.Run("complete status", func(t *testing.T) {
		bad := r
		bad.Status = StatusComplete
		if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "cannot contain unknowns") {
			t.Fatalf("complete report with unknown error = %v", err)
		}
	})
}

func TestValidateRejectsContradictoryInventoryMetadata(t *testing.T) {
	tests := []struct {
		name string
		file File
	}{
		{"inspected-without-digest", File{Path: "plugin.sh", Kind: "regular", Mode: "-rw-r--r--", Inspected: true}},
		{"digest-without-inspection", File{Path: "plugin.sh", Kind: "regular", Mode: "-rw-r--r--", SHA256: strings.Repeat("a", 64)}},
		{"invalid-digest", File{Path: "plugin.sh", Kind: "regular", Mode: "-rw-r--r--", Inspected: true, SHA256: "not-a-digest"}},
		{"inspected-and-skipped", File{Path: "plugin.sh", Kind: "regular", Mode: "-rw-r--r--", Inspected: true, SHA256: strings.Repeat("a", 64), SkipReason: "limit"}},
		{"link-target-on-regular", File{Path: "plugin.sh", Kind: "regular", Mode: "-rw-r--r--", LinkTarget: "elsewhere"}},
		{"binary-on-uninspected-file", File{Path: "helper", Kind: "regular", Mode: "-rwxr-xr-x", Binary: &Binary{Format: "ELF"}}},
		{"binary-on-non-elf", File{Path: "helper", Kind: "regular", Mode: "-rwxr-xr-x", Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "text/plain", Binary: &Binary{Format: "ELF"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := validReport()
			r.Target.FileCount = 1
			r.Inventory = []File{test.file}
			if err := r.Validate(); err == nil {
				t.Fatal("contradictory inventory metadata was accepted")
			}
		})
	}
}

func TestValidateReconcilesInspectedByteTotals(t *testing.T) {
	digest := strings.Repeat("a", 64)
	valid := validReport()
	valid.Target.FileCount = 2
	valid.Target.ReadBytes = 7
	valid.Target.BinaryBytes = 11
	valid.Inventory = []File{
		{Path: "plugin.sh", Kind: "regular", Mode: "-rw-r--r--", Size: 7, Inspected: true, SHA256: digest, ContentType: "text/plain", Analysis: AnalysisAnalyzed},
		{Path: "helper", Kind: "regular", Mode: "-rwxr-xr-x", Size: 11, Inspected: true, SHA256: digest, ContentType: "application/x-elf", Analysis: AnalysisAnalyzed},
	}
	finalizeNativeArtifactReport(&valid)
	if err := valid.Validate(); err != nil {
		t.Fatalf("matching byte totals were rejected: %v", err)
	}

	for _, mutate := range []func(*Report){
		func(r *Report) { r.Target.ReadBytes-- },
		func(r *Report) { r.Target.ReadBytes++ },
		func(r *Report) { r.Target.BinaryBytes-- },
		func(r *Report) { r.Target.BinaryBytes++ },
	} {
		r := valid
		mutate(&r)
		if err := r.Validate(); err == nil {
			t.Fatalf("mismatched byte totals were accepted: %#v", r.Target)
		}
	}
}

func TestValidateRejectsNullContractCollections(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Report)
	}{
		{"inventory", func(r *Report) { r.Inventory = nil }},
		{"operations", func(r *Report) { r.Operations = nil }},
		{"resources", func(r *Report) { r.Resources = nil }},
		{"findings", func(r *Report) { r.Findings = nil }},
		{"limitations", func(r *Report) { r.Limitations = nil }},
		{"errors", func(r *Report) { r.Errors = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := validReport()
			test.mutate(&r)
			if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "JSON arrays") {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}

	r := validReport()
	r.Target.Manifest = &Manifest{Kinds: nil, EntryPoints: map[string]string{}}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "manifest kinds") {
		t.Fatalf("nil manifest kinds error = %v", err)
	}
	r.Target.Manifest = &Manifest{Kinds: []string{}, EntryPoints: nil}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "manifest kinds") {
		t.Fatalf("nil manifest entry points error = %v", err)
	}
}

func TestValidateRequiresCompleteParsedELFMetadata(t *testing.T) {
	digest := strings.Repeat("a", 64)
	valid := validReport()
	valid.Target.FileCount = 1
	valid.Target.BinaryBytes = 10
	valid.Inventory = []File{{
		Path: "helper", Kind: "regular", Mode: "-rwxr-xr-x", Size: 10, Inspected: true,
		SHA256: digest, ContentType: "application/x-elf", Analysis: AnalysisAnalyzed,
		Binary: &Binary{Format: "ELF", Class: "ELFCLASS64", ByteOrder: "ELFDATA2LSB", Machine: "EM_AARCH64", Type: "ET_DYN", Libraries: []string{}, ImportedSymbols: []string{}, ExtractedStrings: []string{}, EmbeddedURLs: []string{}, FileCapabilities: []string{}},
	}}
	finalizeNativeArtifactReport(&valid)
	if err := valid.Validate(); err != nil {
		t.Fatalf("complete ELF metadata was rejected: %v", err)
	}

	for _, mutate := range []func(*Binary){
		func(b *Binary) { b.Format = "PE" },
		func(b *Binary) { b.Class = "" },
		func(b *Binary) { b.ByteOrder = "" },
		func(b *Binary) { b.Machine = "" },
		func(b *Binary) { b.Type = "" },
		func(b *Binary) { b.Libraries = nil },
		func(b *Binary) { b.ImportedSymbols = nil },
		func(b *Binary) { b.ExtractedStrings = nil },
		func(b *Binary) { b.EmbeddedURLs = nil },
		func(b *Binary) { b.FileCapabilities = nil },
	} {
		r := valid
		binaryCopy := *valid.Inventory[0].Binary
		r.Inventory = append([]File(nil), valid.Inventory...)
		r.Inventory[0].Binary = &binaryCopy
		mutate(r.Inventory[0].Binary)
		if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "incomplete ELF metadata") {
			t.Fatalf("invalid ELF metadata error = %v", err)
		}
	}
}

func TestValidateELFNestedCollectionLimits(t *testing.T) {
	base := func() Report {
		r := validReport()
		r.Target.FileCount, r.Target.BinaryBytes = 1, 10
		r.Inventory = []File{{Path: "helper", Kind: "regular", Mode: "-rwxr-xr-x", Size: 10, Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "application/x-elf", Analysis: AnalysisAnalyzed,
			Binary: &Binary{Format: "ELF", Class: "ELFCLASS64", ByteOrder: "ELFDATA2LSB", Machine: "EM_AARCH64", Type: "ET_DYN", Libraries: []string{}, ImportedSymbols: []string{}, ExtractedStrings: []string{}, EmbeddedURLs: []string{}, FileCapabilities: []string{}}}}
		finalizeNativeArtifactReport(&r)
		return r
	}
	tests := []struct {
		name  string
		limit int
		set   func(*Binary, []string)
	}{
		{"imports", MaxImportedSymbols, func(b *Binary, v []string) { b.ImportedSymbols = v }},
		{"strings", MaxExtractedStrings, func(b *Binary, v []string) { b.ExtractedStrings = v }},
		{"URLs", MaxEmbeddedURLs, func(b *Binary, v []string) { b.EmbeddedURLs = v }},
		{"capabilities", MaxFileCapabilities, func(b *Binary, v []string) { b.FileCapabilities = v }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, count := range []int{test.limit, test.limit + 1} {
				r := base()
				values := make([]string, count)
				for index := range values {
					values[index] = fmt.Sprintf("value-%d", index)
				}
				test.set(r.Inventory[0].Binary, values)
				err := r.Validate()
				if count == test.limit && err != nil {
					t.Fatalf("exact limit rejected: %v", err)
				}
				if count > test.limit && (err == nil || !strings.Contains(err.Error(), "collection limit")) {
					t.Fatalf("overage error = %v", err)
				}
			}
		})
	}
}

func TestValidateImportedLibraryLimitExactAndFirstOver(t *testing.T) {
	makeReport := func(count int) Report {
		r := validReport()
		r.Target.FileCount = 1
		r.Target.BinaryBytes = 10
		r.Inventory = []File{{
			Path: "helper", Kind: "regular", Mode: "-rwxr-xr-x", Size: 10, Inspected: true,
			SHA256: strings.Repeat("a", 64), ContentType: "application/x-elf", Analysis: AnalysisAnalyzed,
			Binary: &Binary{Format: "ELF", Class: "ELFCLASS64", ByteOrder: "ELFDATA2LSB", Machine: "EM_AARCH64", Type: "ET_DYN", Libraries: make([]string, count), ImportedSymbols: []string{}, ExtractedStrings: []string{}, EmbeddedURLs: []string{}, FileCapabilities: []string{}},
		}}
		finalizeNativeArtifactReport(&r)
		for index := range r.Inventory[0].Binary.Libraries {
			r.Inventory[0].Binary.Libraries[index] = fmt.Sprintf("lib-%d.so", index)
		}
		return r
	}
	if err := makeReport(MaxImportedLibraries).Validate(); err != nil {
		t.Fatalf("exact imported-library limit rejected: %v", err)
	}
	if err := makeReport(MaxImportedLibraries + 1).Validate(); err == nil || !strings.Contains(err.Error(), "imported libraries") {
		t.Fatalf("first imported-library overage error = %v", err)
	}
}

func TestValidateArchiveMetadataAndNestedLimits(t *testing.T) {
	makeReport := func(count int) Report {
		r := validReport()
		r.Target.FileCount = 1
		r.Target.ReadBytes = 10
		entries := make([]ArchiveEntry, count)
		for index := range entries {
			entries[index] = ArchiveEntry{Path: fmt.Sprintf("entry-%d", index), Kind: "file", Size: 1}
		}
		r.Inventory = []File{{
			Path: "payload.zip", Kind: "regular", Mode: "-rw-------", Size: 10, Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "application/zip", Analysis: AnalysisAnalyzed,
			Archive: &Archive{Format: "zip", Entries: entries, InventoryComplete: count <= MaxArchiveEntries, RetainedUncompressedBytes: int64(count)},
		}}
		finalizeArchiveArtifactReport(&r)
		return r
	}
	if err := makeReport(MaxArchiveEntries).Validate(); err != nil {
		t.Fatalf("exact archive-entry limit rejected: %v", err)
	}
	if err := makeReport(MaxArchiveEntries + 1).Validate(); err == nil || !strings.Contains(err.Error(), "archive entries") {
		t.Fatalf("archive-entry overage error = %v", err)
	}

	for _, mutate := range []func(*Archive){
		func(a *Archive) { a.Format = "rar" },
		func(a *Archive) { a.Entries = nil },
		func(a *Archive) { a.RetainedUncompressedBytes = -1 },
		func(a *Archive) { a.RetainedUncompressedBytes++ },
		func(a *Archive) { a.Entries[0].Path = "" },
		func(a *Archive) { a.Entries[0].Size = -1 },
	} {
		r := makeReport(1)
		mutate(r.Inventory[0].Archive)
		if err := r.Validate(); err == nil {
			t.Fatalf("invalid archive metadata was accepted: %#v", r.Inventory[0].Archive)
		}
	}

	r := makeReport(1)
	r.Inventory[0].Kind = "directory"
	if err := r.Validate(); err == nil {
		t.Fatalf("archive on non-regular inventory error = %v", err)
	}
}

func TestValidateOperationArgumentLimitExactAndFirstOver(t *testing.T) {
	makeReport := func(count int) Report {
		r := validReport()
		r.Operations = []Operation{{ID: "op", Category: "language-call", Command: "call", Arguments: make([]string, count), Scope: ScopeUnknown, Confidence: ConfidenceHigh, Evidence: Evidence{Path: "helper.py", LineStart: 1, LineEnd: 1}}}
		for index := range r.Operations[0].Arguments {
			r.Operations[0].Arguments[index] = "x"
		}
		buildTestEvidence(t, &r)
		return r
	}
	if err := makeReport(MaxOperationArguments).Validate(); err != nil {
		t.Fatalf("exact argument limit rejected: %v", err)
	}
	if err := makeReport(MaxOperationArguments + 1).Validate(); err == nil || !strings.Contains(err.Error(), "arguments exceed") {
		t.Fatalf("first argument overage error = %v", err)
	}
}

func TestValidateRejectsEvidenceEndWithoutStart(t *testing.T) {
	r := validReport()
	r.Operations = []Operation{{
		ID: "operation-1", Category: "process-execution", Command: "example", Scope: ScopeRuntime, Confidence: ConfidenceHigh,
		Evidence: Evidence{Path: "plugin.sh", LineEnd: 5},
	}}
	buildTestEvidence(t, &r)
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "invalid evidence lines") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestSandboxMetadataRequiresResourceLimits(t *testing.T) {
	r := validReport()
	r.Scan.ResourceLimits = nil
	if err := r.Validate(); err == nil {
		t.Fatal("sandboxed report without resource limits was accepted")
	}
	r.Scan.Sandboxed = false
	r.Scan.ResourceLimits = &ResourceLimits{MemoryMaxBytes: 1, TasksMax: 1, CPUQuotaPercent: 1, WallTimeSeconds: 1}
	if err := r.Validate(); err == nil {
		t.Fatal("unsandboxed report claiming resource limits was accepted")
	}
}

func FuzzDecodeNeverPanics(f *testing.F) {
	valid, err := json.Marshal(validReport())
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range [][]byte{
		valid,
		[]byte(`{}`),
		[]byte(`{"schemaVersion":"1.0.0","surprise":true}`),
		[]byte(`[] {}`),
		{0xff, 0xfe, '{', '}', 0x00},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		const maxBrokerReportBytes = 16 << 20
		if len(data) > maxBrokerReportBytes {
			t.Skip()
		}
		decoded, err := Decode(data)
		if err == nil {
			if validateErr := decoded.Validate(); validateErr != nil {
				t.Fatalf("Decode accepted a report that fails Validate: %v", validateErr)
			}
		}
	})
}
