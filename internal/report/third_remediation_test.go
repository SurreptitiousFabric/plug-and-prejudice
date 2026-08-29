package report

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"strings"
	"testing"
	"unicode/utf8"
)

func reverseStrings(values []string) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func TestInventoryRootDigestIsRecomputedAndFieldBound(t *testing.T) {
	empty, err := InventoryRootDigest([]File{})
	if err != nil || empty == "" || len(empty) != 64 {
		t.Fatalf("empty inventory digest = %q, %v", empty, err)
	}
	t.Logf("empty target inventory digest: %s", empty)
	fixtureDigest, err := InventoryRootDigest([]File{{Path: "plugin.sh", Kind: "regular", Mode: "-rw-r--r--", SHA256: strings.Repeat("a", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("golden fixture target inventory digest: %s", fixtureDigest)
	files := []File{
		{Path: "b", Kind: "regular", Mode: "-rw-r--r--", Size: 2, SHA256: strings.Repeat("b", 64), SkipReason: "bounded"},
		{Path: "a", Kind: "symlink", Mode: "Lrwxrwxrwx", LinkTarget: "b"},
	}
	first, err := InventoryRootDigest(files)
	if err != nil {
		t.Fatal(err)
	}
	reordered := []File{files[1], files[0]}
	second, err := InventoryRootDigest(reordered)
	if err != nil || first != second {
		t.Fatalf("reordered digest = %q/%q, %v", first, second, err)
	}

	for _, mutate := range []func(*File){
		func(f *File) { f.Path = "c" }, func(f *File) { f.Kind = "directory" }, func(f *File) { f.Mode = "-r--------" },
		func(f *File) { f.Size++ }, func(f *File) { f.SHA256 = strings.Repeat("c", 64) }, func(f *File) { f.LinkTarget = "elsewhere" },
		func(f *File) { f.SkipReason = "different" },
	} {
		changed := append([]File(nil), files...)
		mutate(&changed[0])
		digest, digestErr := InventoryRootDigest(changed)
		if digestErr != nil {
			t.Fatal(digestErr)
		}
		if digest == first {
			t.Fatalf("covered field mutation did not change %q", first)
		}
	}
	analysisOnly := append([]File(nil), files...)
	analysisOnly[0].Analysis = AnalysisPartial
	analysisOnly[0].AnalysisReason = "later analyzer result"
	analysisOnly[0].ContentType = "application/octet-stream"
	if digest, digestErr := InventoryRootDigest(analysisOnly); digestErr != nil || digest != first {
		t.Fatalf("analysis-only fields changed root digest: %q/%q, %v", first, digest, digestErr)
	}
	withNUL := append([]File(nil), files...)
	withNUL[0].Path = "bad\x00path"
	if _, err := InventoryRootDigest(withNUL); err == nil {
		t.Fatal("NUL-containing inventory observation was accepted")
	}

	r := validReport()
	if r.Target.RootDigest != empty || r.EvidenceInputs[0].SubjectRootDigest != empty {
		t.Fatalf("producer/validator empty digest mismatch: report=%q input=%q calculated=%q", r.Target.RootDigest, r.EvidenceInputs[0].SubjectRootDigest, empty)
	}
	forged := r
	forged.Target.RootDigest = strings.Repeat("a", 64)
	forged.EvidenceInputs = append([]EvidenceInput(nil), r.EvidenceInputs...)
	forged.EvidenceInputs[0].SubjectRootDigest = forged.Target.RootDigest
	if err := forged.Validate(); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("forged digest result = %v", err)
	}
	changedAfterDigest := validReport()
	changedAfterDigest.Inventory = []File{{Path: "plugin.sh", Kind: "regular", Mode: "-rw-r--r--", Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "text/plain", Analysis: AnalysisAnalyzed}}
	changedAfterDigest.Target.FileCount = 1
	refreshTestRootDigest(&changedAfterDigest)
	changedAfterDigest.Inventory[0].Mode = "-r--------"
	if err := changedAfterDigest.Validate(); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("post-digest inventory mutation result = %v", err)
	}

	encoded, err := EncodeCanonical(r)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil || decoded.Target.RootDigest != empty || decoded.EvidenceInputs[0].SubjectRootDigest != empty {
		t.Fatalf("canonical digest round trip = %q/%q, %v", decoded.Target.RootDigest, decoded.EvidenceInputs[0].SubjectRootDigest, err)
	}
}

func TestTargetEvidenceInputIdentityFormatAndUniqueness(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Report)
	}{
		{"missing-subject-root-digest", func(r *Report) { r.Target.RootDigest = ""; r.EvidenceInputs[0].SubjectRootDigest = "" }},
		{"target-document-digest", func(r *Report) { r.EvidenceInputs[0].DocumentSHA256 = strings.Repeat("a", 64) }},
		{"wrong-format", func(r *Report) { r.EvidenceInputs[0].Format = "other" }},
		{"wrong-version", func(r *Report) { r.EvidenceInputs[0].Version = "1.0.0" }},
		{"second-target", func(r *Report) {
			r.EvidenceInputs = append(r.EvidenceInputs, EvidenceInput{ID: "input-target-2", Type: EvidenceInputTarget, Label: "second", SubjectRootDigest: r.Target.RootDigest, Format: TargetEvidenceInputFormat, Version: TargetEvidenceInputVersion})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := validReport()
			test.mutate(&r)
			if err := r.Validate(); err == nil {
				t.Fatal("invalid target evidence input accepted")
			}
		})
	}
}

func producerUTFReport(t *testing.T) Report {
	t.Helper()
	r := graphReport(t)
	return r
}

func TestProducerRejectsInvalidUTF8WithoutPartialOutput(t *testing.T) {
	invalid := []string{string([]byte{0xff}), string([]byte{0xc0})}
	if first, _ := json.Marshal(invalid[0]); true {
		second, _ := json.Marshal(invalid[1])
		if !bytes.Equal(first, second) {
			t.Fatalf("negative control encodings differ: %q/%q", first, second)
		}
	}
	for _, value := range invalid {
		tests := []struct {
			name   string
			mutate func(*Report)
		}{
			{"inventory-path", func(r *Report) { r.Inventory[0].Path = value }},
			{"operation-command", func(r *Report) { r.Operations[0].Command = value }},
			{"evidence-excerpt", func(r *Report) { r.Operations[0].Evidence.Excerpt = value }},
			{"internal-id", func(r *Report) { r.Operations[0].ID = value; _ = r.BuildEvidenceGraph() }},
			{"manifest-map-key", func(r *Report) {
				r.Target.Manifest = &Manifest{ID: "m", Name: "m", Version: "1", Kinds: []string{}, EntryPoints: map[string]string{value: "plugin.sh"}}
			}},
			{"external-input-label", func(r *Report) {
				r.EvidenceInputs = append(r.EvidenceInputs, EvidenceInput{ID: "input-omarchy", Type: EvidenceInputOmarchyAudit, Label: value, DocumentSHA256: strings.Repeat("b", 64), Format: OmarchyAuditInputFormat, Version: OmarchyAuditInputVersion})
			}},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				r := producerUTFReport(t)
				test.mutate(&r)
				if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
					t.Fatalf("Validate() = %v", err)
				}
				if _, err := EncodeCanonical(r); err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
					t.Fatalf("EncodeCanonical() = %v", err)
				}
				var destination bytes.Buffer
				if err := WriteCanonical(&destination, r); err == nil || !strings.Contains(err.Error(), "invalid UTF-8") || destination.Len() != 0 {
					t.Fatalf("WriteCanonical() = %v, bytes=%d", err, destination.Len())
				}
			})
		}
	}
	r := validReport()
	r.Target.DisplayName = "valid replacement character: �"
	encoded, err := EncodeCanonical(r)
	if err != nil {
		t.Fatalf("genuine U+FFFD rejected: %v", err)
	}
	decoded, err := Decode(encoded)
	if err != nil || decoded.Target.DisplayName != r.Target.DisplayName {
		t.Fatalf("U+FFFD round trip = %q, %v", decoded.Target.DisplayName, err)
	}
}

func nativeReport(t *testing.T, native Unknown, external bool) Report {
	t.Helper()
	r := validReport()
	r.Status = StatusIncomplete
	r.Inventory = []File{{Path: "helper", Kind: "regular", Mode: "-rwxr-xr-x", Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "application/x-elf", Analysis: AnalysisPartial, AnalysisReason: "metadata only"}, {Path: "other", Kind: "regular", Mode: "-rw-r--r--", Analysis: AnalysisUnanalyzed, AnalysisReason: "not inspected"}}
	r.Target.FileCount = len(r.Inventory)
	refreshTestRootDigest(&r)
	if external {
		appendTestExternalInput(&r, "input-omarchy")
	}
	r.Unknowns = append(r.Unknowns, native)
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		t.Fatal(err)
	}
	return r
}

func nativeUnknown(evidence Evidence, provenance Provenance, scope Scope) Unknown {
	return Unknown{ID: "unknown-native", Category: "native-behavior", Reason: UnknownNativeBehavior, Scope: scope, Confidence: ConfidenceHigh, Title: "Native behavior unresolved", Description: "Metadata does not establish native behavior.", Evidence: []Evidence{evidence}, Origins: []ValueOrigin{}, AffectedOperations: []string{}, SuppressedRules: []string{}, Provenance: provenance}
}

func TestNativeUnknownMustBeLocalAndTargetAnchored(t *testing.T) {
	external := Provenance{RuleID: OmarchyAuditObservationRule, Analyzer: OmarchyAuditAnalyzer, AnalyzerVersion: OmarchyAuditInputVersion, EvidenceSource: EvidenceSourceOmarchyAudit}
	tests := []struct {
		name   string
		report func(*testing.T) Report
		valid  bool
	}{
		{"external-same-path", func(t *testing.T) Report {
			return nativeReport(t, nativeUnknown(Evidence{InputID: "input-omarchy", Path: "helper"}, external, ScopeRuntime), true)
		}, false},
		{"local-wrong-input", func(t *testing.T) Report {
			return nativeReport(t, nativeUnknown(Evidence{InputID: "input-omarchy", Path: "helper"}, testProvenance, ScopeRuntime), true)
		}, false},
		{"local-other-file", func(t *testing.T) Report {
			return nativeReport(t, nativeUnknown(Evidence{InputID: TargetEvidenceInputID, Path: "other"}, testProvenance, ScopeRuntime), false)
		}, false},
		{"tooling-scope", func(t *testing.T) Report {
			return nativeReport(t, nativeUnknown(Evidence{InputID: TargetEvidenceInputID, Path: "helper"}, testProvenance, ScopeTooling), false)
		}, false},
		{"local-target", func(t *testing.T) Report {
			return nativeReport(t, nativeUnknown(Evidence{InputID: TargetEvidenceInputID, Path: "helper"}, testProvenance, ScopeRuntime), false)
		}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := test.report(t)
			err := r.Validate()
			if test.valid && err != nil {
				t.Fatal(err)
			}
			if !test.valid && err == nil {
				t.Fatal("invalid native unknown accepted")
			}
		})
	}
}

func TestSnapshotUnboundExternalInputsRequireExactBindingUnknown(t *testing.T) {
	without := validReport()
	without.EvidenceInputs = append(without.EvidenceInputs, NewOmarchyAuditEvidenceInput("input-omarchy", "audit", []byte(`{"commands":["curl"]}`)))
	if err := without.Validate(); err == nil || !strings.Contains(err.Error(), "binding unknown") {
		t.Fatalf("missing binding result = %v", err)
	}

	valid := validReport()
	appendTestExternalInput(&valid, "input-omarchy")
	if err := valid.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	if err := valid.BuildReviewSummary(coverageFromInventory(valid.Inventory)); err != nil {
		t.Fatal(err)
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid binding unknown rejected: %v", err)
	}

	wrong := valid
	wrong.Unknowns = append([]Unknown(nil), valid.Unknowns...)
	wrong.EvidenceInputs = append([]EvidenceInput(nil), valid.EvidenceInputs...)
	wrong.EvidenceInputs = append(wrong.EvidenceInputs, NewOmarchyAuditEvidenceInput("input-other-external", "other audit", []byte(`{"commands":["wget"]}`)))
	wrong.Unknowns[0].Evidence = []Evidence{{InputID: "input-other-external", Path: "other-audit.json"}}
	if err := wrong.Validate(); err == nil {
		t.Fatal("binding unknown for wrong input accepted")
	}

	malformed := valid
	malformed.Unknowns = append([]Unknown(nil), valid.Unknowns...)
	malformed.Unknowns[0].SuppressedRules = []string{"other"}
	if err := malformed.Validate(); err == nil || !strings.Contains(err.Error(), "structural shape") {
		t.Fatalf("malformed binding result = %v", err)
	}

	mismatch := valid
	mismatch.Operations = []Operation{{ID: "external", Category: "external", Command: "curl", Scope: ScopeUnknown, Confidence: ConfidenceHigh, Evidence: Evidence{InputID: "input-omarchy", Path: "audit.json"}, Provenance: Provenance{RuleID: OmarchyAuditObservationRule, Analyzer: OmarchyAuditAnalyzer, AnalyzerVersion: "wrong", EvidenceSource: EvidenceSourceOmarchyAudit}}}
	if err := mismatch.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	if err := mismatch.BuildReviewSummary(coverageFromInventory(mismatch.Inventory)); err != nil {
		t.Fatal(err)
	}
	if err := mismatch.Validate(); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("provenance version mismatch result = %v", err)
	}
}

func coverageComparisonReport(t *testing.T, externalOnly bool) Report {
	t.Helper()
	r := graphReport(t)
	external := appendTestExternalInput(&r, "input-omarchy")
	sourceKind, sourceID := NodeOperation, "operation-1"
	sourceEvidence, sourceProvenance := r.Operations[0].Evidence, r.Operations[0].Provenance
	if externalOnly {
		externalEvidence := Evidence{InputID: "input-omarchy", Path: "omarchy-audit.json", Operation: "observed command: wget"}
		r.Operations = append(r.Operations, Operation{ID: "external-wget", Category: "omarchy-audit-command", Command: "wget", Arguments: []string{}, Scope: ScopeUnknown, Confidence: ConfidenceHigh, Evidence: externalEvidence, Provenance: external})
		sourceID, sourceEvidence, sourceProvenance = "external-wget", externalEvidence, external
	}
	findingProvenance := sourceProvenance
	findingProvenance.RuleID = CoverageComparisonRule
	r.Findings = append(r.Findings, Finding{ID: "coverage-difference", Claim: ClaimFact, Severity: SeverityInformational, Confidence: ConfidenceHigh, Category: CoverageDifferenceCategory, Scope: ScopeUnknown, Title: "Coverage differs", Explanation: "One source retained this observation while the compared source retained no matching observation.", Evidence: []Evidence{sourceEvidence}, Related: []string{}, Provenance: findingProvenance})
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	subject, ok := r.semanticSubject(sourceKind, sourceID)
	if !ok {
		t.Fatal("missing semantic subject")
	}
	if err := r.AddComparison(Comparison{Type: RelationshipDisagreesWith, FromKind: sourceKind, FromID: sourceID, ToKind: NodeFinding, ToID: "coverage-difference", Basis: ComparisonBasis{Kind: "coverage", Subject: subject}}); err != nil {
		t.Fatal(err)
	}
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCoverageDisagreementRequiresExactProducerShape(t *testing.T) {
	for _, externalOnly := range []bool{false, true} {
		r := coverageComparisonReport(t, externalOnly)
		if err := r.Validate(); err != nil {
			t.Fatalf("valid direction external=%v rejected: %v", externalOnly, err)
		}
	}
	mutations := []struct {
		name   string
		mutate func(*Finding)
	}{
		{"claim", func(f *Finding) { f.Claim = ClaimInference }},
		{"severity", func(f *Finding) { f.Severity = SeverityLow }},
		{"scope", func(f *Finding) { f.Scope = ScopeRuntime }},
		{"provenance", func(f *Finding) { f.Provenance.Analyzer = "other/analyzer" }},
		{"evidence", func(f *Finding) { f.Evidence[0].Excerpt = "unrelated" }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			r := coverageComparisonReport(t, true)
			for index := range r.Findings {
				if r.Findings[index].ID == "coverage-difference" {
					test.mutate(&r.Findings[index])
				}
			}
			if err := r.Validate(); err == nil {
				t.Fatal("malformed coverage disagreement accepted")
			}
		})
	}

	noContext := graphReport(t)
	source := noContext.Operations[0]
	provenance := source.Provenance
	provenance.RuleID = CoverageComparisonRule
	noContext.Findings = append(noContext.Findings, Finding{ID: "magic", Claim: ClaimFact, Severity: SeverityInformational, Confidence: ConfidenceHigh, Category: CoverageDifferenceCategory, Scope: ScopeUnknown, Title: "magic", Explanation: "magic", Evidence: []Evidence{source.Evidence}, Related: []string{}, Provenance: provenance})
	if err := noContext.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	if err := noContext.AddComparison(Comparison{Type: RelationshipDisagreesWith, FromKind: NodeOperation, FromID: source.ID, ToKind: NodeFinding, ToID: "magic", Basis: ComparisonBasis{Kind: "coverage", Subject: "command\x00curl"}}); err == nil {
		t.Fatal("coverage disagreement without external comparison context accepted")
	}

	unrelated := coverageComparisonReport(t, true)
	for index := range unrelated.Findings {
		if unrelated.Findings[index].ID == "coverage-difference" {
			unrelated.Findings[index].Evidence[0].Path = "different.json"
		}
	}
	if err := unrelated.Validate(); err == nil {
		t.Fatal("unrelated magic-category finding accepted")
	}

	basis := coverageComparisonReport(t, true)
	for index := range basis.Relationships {
		if basis.Relationships[index].Type == RelationshipDisagreesWith {
			basis.Relationships[index].Comparison.Subject = "command\x00curl"
		}
	}
	if err := basis.Validate(); err == nil {
		t.Fatal("mismatched coverage basis accepted")
	}

	matched := coverageComparisonReport(t, true)
	matched.Operations = append(matched.Operations, Operation{ID: "local-wget", Category: "execution", Command: "wget", Arguments: []string{}, Scope: ScopeRuntime, Confidence: ConfidenceHigh, Evidence: Evidence{InputID: TargetEvidenceInputID, Path: "plugin.sh"}, Provenance: testProvenance})
	if err := matched.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	if err := matched.AddComparison(Comparison{Type: RelationshipDisagreesWith, FromKind: NodeOperation, FromID: "external-wget", ToKind: NodeFinding, ToID: "coverage-difference", Basis: ComparisonBasis{Kind: "coverage", Subject: "command\x00wget"}}); err == nil {
		t.Fatal("coverage disagreement accepted despite an opposite-source exact match")
	}
}

func comparisonCollisionReport(t *testing.T) (Report, Comparison, Comparison) {
	t.Helper()
	r := graphReport(t)
	external := appendTestExternalInput(&r, "input-omarchy")
	r.Operations = append(r.Operations,
		Operation{ID: "external-one", Category: "external", Command: "curl", Arguments: []string{}, Scope: ScopeUnknown, Confidence: ConfidenceHigh, Evidence: Evidence{InputID: "input-omarchy", Path: "audit.json", LineStart: 1}, Provenance: external},
		Operation{ID: "external-two", Category: "external", Command: "curl", Arguments: []string{}, Scope: ScopeUnknown, Confidence: ConfidenceHigh, Evidence: Evidence{InputID: "input-omarchy", Path: "audit.json", LineStart: 2}, Provenance: external},
	)
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	first := Comparison{Type: RelationshipCorroborates, FromKind: NodeOperation, FromID: "external-one", ToKind: NodeOperation, ToID: "operation-1"}
	second := Comparison{Type: RelationshipCorroborates, FromKind: NodeOperation, FromID: "external-two", ToKind: NodeOperation, ToID: "operation-1"}
	return r, first, second
}

func TestAddComparisonForcedCollisionFailsClosed(t *testing.T) {
	forced := func([]byte) [32]byte { return [32]byte{} }
	t.Run("exact-duplicate", func(t *testing.T) {
		r, first, _ := comparisonCollisionReport(t)
		if err := r.addComparisonWithDigest(first, forced); err != nil {
			t.Fatal(err)
		}
		if err := r.addComparisonWithDigest(first, forced); err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, edge := range r.Relationships {
			if edge.ID == "PE-00000000000000000000000000000000" {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("forced comparison count = %d", count)
		}
	})
	t.Run("different-endpoints", func(t *testing.T) {
		r, first, second := comparisonCollisionReport(t)
		if err := r.addComparisonWithDigest(first, forced); err != nil {
			t.Fatal(err)
		}
		if err := r.addComparisonWithDigest(second, forced); err == nil || !strings.Contains(err.Error(), "collision") {
			t.Fatalf("collision result = %v", err)
		}
	})
	for _, test := range []struct {
		name   string
		mutate func(*Relationship)
	}{
		{"different-type", func(edge *Relationship) { edge.Type = RelationshipDuplicates }},
		{"different-basis", func(edge *Relationship) { edge.Comparison = &ComparisonBasis{Kind: "operation", Subject: "forged"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, first, _ := comparisonCollisionReport(t)
			if err := r.addComparisonWithDigest(first, forced); err != nil {
				t.Fatal(err)
			}
			for index := range r.Relationships {
				if r.Relationships[index].ID == "PE-00000000000000000000000000000000" {
					test.mutate(&r.Relationships[index])
				}
			}
			if err := r.addComparisonWithDigest(first, forced); err == nil || !strings.Contains(err.Error(), "collision") {
				t.Fatalf("collision result = %v", err)
			}
		})
	}
}

func nestedCanonicalReport(t *testing.T) Report {
	t.Helper()
	r := validReport()
	r.Status = StatusIncomplete
	r.Target.Manifest = &Manifest{ID: "m", Name: "m", Version: "1", Kinds: []string{"qml", "javascript"}, EntryPoints: map[string]string{"z": "payload.zip", "a": "plugin.sh"}}
	r.Inventory = []File{
		{Path: "plugin.sh", Kind: "regular", Mode: "-rw-r--r--", Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "text/plain", Analysis: AnalysisAnalyzed},
		{Path: "helper", Kind: "regular", Mode: "-rwxr-xr-x", Inspected: true, SHA256: strings.Repeat("b", 64), ContentType: "application/x-elf", Analysis: AnalysisPartial, AnalysisReason: "metadata only", Binary: &Binary{Format: "ELF", Class: "ELFCLASS64", ByteOrder: "ELFDATA2LSB", Machine: "EM_X86_64", Type: "ET_DYN", Libraries: []string{"z.so", "a.so"}, ImportedSymbols: []string{"z", "a"}, ExtractedStrings: []string{"z", "a"}, EmbeddedURLs: []string{"https://z", "https://a"}, FileCapabilities: []string{"cap_z", "cap_a"}}},
		{Path: "payload.zip", Kind: "regular", Mode: "-rw-r--r--", Inspected: true, SHA256: strings.Repeat("c", 64), ContentType: "application/zip", Analysis: AnalysisPartial, AnalysisReason: "inventory only", Archive: &Archive{Format: "zip", Entries: []ArchiveEntry{{Path: "first", Kind: "regular"}, {Path: "second", Kind: "regular"}}, InventoryComplete: true}},
	}
	r.Target.FileCount = len(r.Inventory)
	refreshTestRootDigest(&r)
	e1 := Evidence{InputID: TargetEvidenceInputID, Path: "plugin.sh", LineStart: 1}
	e2 := Evidence{InputID: TargetEvidenceInputID, Path: "plugin.sh", LineStart: 2}
	r.Operations = []Operation{
		{ID: "op-a", Category: "execution", Command: "cmd", Arguments: []string{"first", "second"}, Scope: ScopeRuntime, Confidence: ConfidenceHigh, Evidence: e1, Provenance: testProvenance},
		{ID: "op-b", Category: "execution", Command: "other", Arguments: []string{}, Scope: ScopeRuntime, Confidence: ConfidenceHigh, Evidence: e2, Provenance: testProvenance},
	}
	r.Findings = []Finding{{ID: "finding", Claim: ClaimFact, Severity: SeverityLow, Confidence: ConfidenceHigh, Category: "test", Scope: ScopeRuntime, Title: "test", Explanation: "test", Evidence: []Evidence{e2, e1}, Related: []string{"op-b", "op-a"}, Provenance: testProvenance}}
	r.Unknowns = []Unknown{
		nativeUnknown(Evidence{InputID: TargetEvidenceInputID, Path: "helper"}, testProvenance, ScopeRuntime),
		{ID: "unknown-flow", Category: "flow", Reason: UnknownDynamicValue, Scope: ScopeRuntime, Confidence: ConfidenceHigh, Title: "flow", Description: "flow", Evidence: []Evidence{e2, e1}, Origins: []ValueOrigin{{Kind: OriginAssignment, Name: "first", Evidence: e1}, {Kind: OriginUseSite, Name: "second", Evidence: e2}}, AffectedOperations: []string{"op-b", "op-a"}, SuppressedRules: []string{"z", "a"}, Provenance: testProvenance},
	}
	r.Limitations = []Limitation{{Code: "archive", Description: "archive semantics remain partial", Path: "payload.zip", Scope: ScopeUnknown}}
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	return r
}

func cloneReportForTest(t *testing.T, value Report) Report {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result Report
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestNestedCanonicalOrderClassification(t *testing.T) {
	base := nestedCanonicalReport(t)
	before, _ := json.Marshal(base)
	want, err := EncodeCanonical(base)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(base)
	if !bytes.Equal(before, after) {
		t.Fatal("canonical encoding mutated caller report")
	}

	random := rand.New(rand.NewSource(23))
	for iteration := 0; iteration < 100; iteration++ {
		nonsemantic := cloneReportForTest(t, base)
		random.Shuffle(len(nonsemantic.Target.Manifest.Kinds), func(i, j int) {
			nonsemantic.Target.Manifest.Kinds[i], nonsemantic.Target.Manifest.Kinds[j] = nonsemantic.Target.Manifest.Kinds[j], nonsemantic.Target.Manifest.Kinds[i]
		})
		nonsemantic.Target.Manifest.EntryPoints = map[string]string{}
		if iteration%2 == 0 {
			nonsemantic.Target.Manifest.EntryPoints["a"] = "plugin.sh"
			nonsemantic.Target.Manifest.EntryPoints["z"] = "payload.zip"
		} else {
			nonsemantic.Target.Manifest.EntryPoints["z"] = "payload.zip"
			nonsemantic.Target.Manifest.EntryPoints["a"] = "plugin.sh"
		}
		for _, binary := range []*Binary{nonsemantic.Inventory[0].Binary, nonsemantic.Inventory[1].Binary, nonsemantic.Inventory[2].Binary} {
			if binary == nil {
				continue
			}
			for _, values := range [][]string{binary.Libraries, binary.ImportedSymbols, binary.ExtractedStrings, binary.EmbeddedURLs, binary.FileCapabilities} {
				random.Shuffle(len(values), func(i, j int) { values[i], values[j] = values[j], values[i] })
			}
		}
		random.Shuffle(len(nonsemantic.Findings[0].Related), func(i, j int) {
			nonsemantic.Findings[0].Related[i], nonsemantic.Findings[0].Related[j] = nonsemantic.Findings[0].Related[j], nonsemantic.Findings[0].Related[i]
		})
		random.Shuffle(len(nonsemantic.Findings[0].Evidence), func(i, j int) {
			nonsemantic.Findings[0].Evidence[i], nonsemantic.Findings[0].Evidence[j] = nonsemantic.Findings[0].Evidence[j], nonsemantic.Findings[0].Evidence[i]
		})
		flow := &nonsemantic.Unknowns[1]
		random.Shuffle(len(flow.Evidence), func(i, j int) { flow.Evidence[i], flow.Evidence[j] = flow.Evidence[j], flow.Evidence[i] })
		random.Shuffle(len(flow.AffectedOperations), func(i, j int) {
			flow.AffectedOperations[i], flow.AffectedOperations[j] = flow.AffectedOperations[j], flow.AffectedOperations[i]
		})
		random.Shuffle(len(flow.SuppressedRules), func(i, j int) {
			flow.SuppressedRules[i], flow.SuppressedRules[j] = flow.SuppressedRules[j], flow.SuppressedRules[i]
		})
		got, err := EncodeCanonical(nonsemantic)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("non-semantic nested shuffle %d changed canonical bytes", iteration)
		}
	}

	for _, test := range []struct {
		name   string
		mutate func(*Report)
	}{
		{"operation-arguments", func(r *Report) { reverseStrings(r.Operations[0].Arguments) }},
		{"data-flow-origins", func(r *Report) {
			r.Unknowns[1].Origins[0], r.Unknowns[1].Origins[1] = r.Unknowns[1].Origins[1], r.Unknowns[1].Origins[0]
		}},
		{"archive-entry-order", func(r *Report) {
			r.Inventory[2].Archive.Entries[0], r.Inventory[2].Archive.Entries[1] = r.Inventory[2].Archive.Entries[1], r.Inventory[2].Archive.Entries[0]
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneReportForTest(t, base)
			test.mutate(&changed)
			encoded, err := EncodeCanonical(changed)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(want, encoded) {
				t.Fatal("semantic order change was canonicalized away")
			}
		})
	}
}

func FuzzEncodeCanonicalNeverPanics(f *testing.F) {
	for _, seed := range [][]byte{[]byte("plain"), []byte("�"), {0xff}, {0xc0, 0xaf}, []byte("<script>")} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		r := validReport()
		r.Target.DisplayName = string(input)
		var destination bytes.Buffer
		err := WriteCanonical(&destination, r)
		if !utf8.Valid(input) {
			if err == nil || destination.Len() != 0 {
				t.Fatalf("invalid UTF-8 encoded: err=%v bytes=%d", err, destination.Len())
			}
			return
		}
		if err == nil && destination.Len() > MaxEncodedReportBytes {
			t.Fatalf("successful encoding exceeded limit: %d", destination.Len())
		}
		if err != nil && destination.Len() != 0 {
			t.Fatalf("failed encoding wrote %d bytes: %v", destination.Len(), err)
		}
	})
}
