package report

import (
	"crypto/sha256"
	"reflect"
	"strings"
	"testing"
)

func collidingDigest([]byte) [32]byte { return [32]byte{} }

func relationshipCollidingDigest(data []byte) [32]byte {
	if strings.HasPrefix(string(data), string(RelationshipDerivedFrom)) || strings.HasPrefix(string(data), string(RelationshipEstablishedBy)) || strings.HasPrefix(string(data), string(RelationshipInferredFrom)) || strings.HasPrefix(string(data), string(RelationshipUnknownBecause)) {
		return [32]byte{}
	}
	return sha256.Sum256(data)
}

func graphReport(t *testing.T) Report {
	t.Helper()
	r := validReport()
	r.Inventory = []File{{Path: "plugin.sh", Kind: "regular", Mode: "-rw-r--r--", Size: 0, Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "text/plain", Analysis: AnalysisAnalyzed}}
	r.Target.FileCount = 1
	evidence := Evidence{Path: "plugin.sh", LineStart: 1, LineEnd: 1, Operation: "curl https://example.test"}
	r.Operations = []Operation{{ID: "operation-1", Category: "process-execution", Command: "curl", Scope: ScopeRuntime, Confidence: ConfidenceHigh, Evidence: evidence, Provenance: testProvenance}}
	r.Resources = []Resource{{ID: "resource-1", Kind: "network-domain", Access: "connect", Value: "example.test", Scope: ScopeRuntime, Confidence: ConfidenceHigh, Evidence: evidence, RelatedOperationID: "operation-1", Provenance: testProvenance}}
	r.Findings = []Finding{
		{ID: "finding-fact", Claim: ClaimFact, Severity: SeverityInformational, Confidence: ConfidenceHigh, Category: "network", Scope: ScopeRuntime, Title: "Network", Explanation: "Names a domain.", Evidence: []Evidence{evidence}, Related: []string{"operation-1"}, Provenance: testProvenance},
		{ID: "finding-inference", Claim: ClaimInference, Severity: SeverityLow, Confidence: ConfidenceMedium, Category: "purpose", Scope: ScopeRuntime, Title: "Purpose", Explanation: "Purpose is inferred.", Evidence: []Evidence{evidence}, Related: []string{"operation-1"}, Provenance: testProvenance},
	}
	r.Status = StatusIncomplete
	r.Unknowns = []Unknown{{ID: "unknown-command", Category: "unresolved-command", Reason: UnknownDynamicValue, Scope: ScopeRuntime, Confidence: ConfidenceHigh,
		Title: "Command unresolved", Description: "The executable is runtime-selected.", Evidence: []Evidence{evidence},
		Origins: []ValueOrigin{{Kind: OriginParameterExpansion, Name: "helper", Evidence: evidence}}, AffectedOperations: []string{"operation-1"},
		SuppressedRules: []string{"command-capability/v1"}, Provenance: testProvenance}}
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestBuildEvidenceGraphAssignsStableReferencesAndTypedEdges(t *testing.T) {
	r := graphReport(t)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, reference := range []string{r.Operations[0].Reference, r.Resources[0].Reference, r.Findings[0].Reference, r.Findings[1].Reference, r.Unknowns[0].Reference} {
		if !strings.HasPrefix(reference, "PP-") || len(reference) != len("PP-")+32 {
			t.Fatalf("invalid public reference %q", reference)
		}
	}
	wantTypes := map[RelationshipType]bool{
		RelationshipDerivedFrom:    false,
		RelationshipEstablishedBy:  false,
		RelationshipInferredFrom:   false,
		RelationshipUnknownBecause: false,
	}
	for _, relationship := range r.Relationships {
		if _, wanted := wantTypes[relationship.Type]; wanted {
			wantTypes[relationship.Type] = true
		}
	}
	for kind, seen := range wantTypes {
		if !seen {
			t.Errorf("missing relationship type %q: %#v", kind, r.Relationships)
		}
	}
}

func TestEvidenceReferencesDoNotDependOnCollectionPosition(t *testing.T) {
	first := graphReport(t)
	second := graphReport(t)
	second.Operations = append([]Operation{{ID: "operation-0", Category: "process-execution", Command: "true", Scope: ScopeTooling, Confidence: ConfidenceHigh, Evidence: Evidence{Path: "tool.sh", LineStart: 1}, Provenance: testProvenance}}, second.Operations...)
	if err := second.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	if first.Operations[0].Reference != second.Operations[1].Reference || first.Findings[0].Reference != second.Findings[0].Reference {
		t.Fatalf("unrelated insertion renumbered stable references: first=%#v second=%#v", first, second)
	}
	before := append([]Relationship(nil), second.Relationships...)
	if err := second.BuildEvidenceGraph(); err != nil || !reflect.DeepEqual(before, second.Relationships) {
		t.Fatalf("evidence graph rebuild is not deterministic: %v\nbefore=%#v\nafter=%#v", err, before, second.Relationships)
	}
}

func TestForcedPublicReferenceCollisionFailsClosed(t *testing.T) {
	r := graphReport(t)
	if err := r.buildEvidenceGraphWithDigest(collidingDigest); err == nil || !strings.Contains(err.Error(), "public reference collision") {
		t.Fatalf("forced public collision result = %v", err)
	}
}

func TestForcedRelationshipCollisionsAndRequiredTuplesFailClosed(t *testing.T) {
	r := graphReport(t)
	if err := r.buildEvidenceGraphWithDigest(relationshipCollidingDigest); err == nil || !strings.Contains(err.Error(), "relationship ID collision") {
		t.Fatalf("forced relationship collision result = %v", err)
	}
	r = graphReport(t)
	kinds, provenance := testReferenceMaps(r)
	for index := range r.Relationships {
		r.Relationships[index].ID = relationshipIDWithDigest(r.Relationships[index].Type, r.Relationships[index].FromKind, r.Relationships[index].From, r.Relationships[index].ToKind, r.Relationships[index].To, relationshipCollidingDigest)
	}
	r.Relationships = r.Relationships[:1]
	if err := validateRelationshipsWithDigest(r, kinds, provenance, relationshipCollidingDigest); err == nil || (!strings.Contains(err.Error(), "missing") && !strings.Contains(err.Error(), "collision")) {
		t.Fatalf("one colliding edge satisfied multiple required tuples: %v", err)
	}
}

func testReferenceMaps(r Report) (map[string]NodeKind, map[string]Provenance) {
	kinds := map[string]NodeKind{}
	provenance := map[string]Provenance{}
	for _, item := range r.Operations {
		kinds[item.Reference] = NodeOperation
		provenance[item.Reference] = item.Provenance
	}
	for _, item := range r.Resources {
		kinds[item.Reference] = NodeResource
		provenance[item.Reference] = item.Provenance
	}
	for _, item := range r.Findings {
		kinds[item.Reference] = NodeFinding
		provenance[item.Reference] = item.Provenance
	}
	for _, item := range r.Unknowns {
		kinds[item.Reference] = NodeUnknown
		provenance[item.Reference] = item.Provenance
	}
	return kinds, provenance
}

func TestValidateRejectsMissingForgedAndMistypedRelationships(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		r := graphReport(t)
		r.Relationships = r.Relationships[1:]
		if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "required evidence relationship") {
			t.Fatalf("missing relationship error = %v", err)
		}
	})
	t.Run("forged public reference", func(t *testing.T) {
		r := graphReport(t)
		r.Findings[0].Reference = "PP-0000000000000000"
		if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "identity") {
			t.Fatalf("forged reference error = %v", err)
		}
	})
	t.Run("mistyped", func(t *testing.T) {
		r := graphReport(t)
		r.Relationships[0].FromKind = NodeOperation
		if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "typed endpoints") {
			t.Fatalf("mistyped relationship error = %v", err)
		}
	})
}

func TestCorroborationAndDuplicationRequireCorrectEvidenceSources(t *testing.T) {
	r := graphReport(t)
	external := testProvenance
	external.Analyzer = "omarchy/plugin-audit"
	external.AnalyzerVersion = "pr8439-test"
	external.EvidenceSource = EvidenceSourceOmarchyAudit
	r.EvidenceInputs = append(r.EvidenceInputs, EvidenceInput{ID: "input-omarchy", Type: EvidenceInputOmarchyAudit, Label: "pinned Omarchy audit", Format: "omarchy-plugin-audit", Version: "pr8439-test"})
	r.Findings = append(r.Findings, Finding{ID: "external-finding", Claim: ClaimFact, Severity: SeverityInformational, Confidence: ConfidenceHigh, Category: "network", Scope: ScopeRuntime, Title: "External network observation", Explanation: "Imported bounded evidence.", Evidence: []Evidence{{Path: "omarchy-audit.json"}}, Provenance: external})
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	from, to := r.Findings[0].Reference, r.Findings[len(r.Findings)-1].Reference
	if from > to {
		from, to = to, from
	}
	corroborates := Relationship{Type: RelationshipCorroborates, FromKind: NodeFinding, From: from, ToKind: NodeFinding, To: to, Comparison: &ComparisonBasis{Kind: "finding", Subject: "network"}}
	corroborates.ID = relationshipID(corroborates.Type, corroborates.FromKind, corroborates.From, corroborates.ToKind, corroborates.To)
	r.Relationships = append(r.Relationships, corroborates)
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "semantic subject") {
		t.Fatalf("unrelated finding corroboration result: %v", err)
	}

	duplicates := graphReport(t)
	repeated := duplicates.Findings[0]
	repeated.ID = "finding-fact-repeat"
	repeated.Reference = ""
	duplicates.Findings = append(duplicates.Findings, repeated)
	if err := duplicates.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	duplicateFrom, duplicateTo := duplicates.Findings[0].Reference, duplicates.Findings[len(duplicates.Findings)-1].Reference
	if duplicateFrom > duplicateTo {
		duplicateFrom, duplicateTo = duplicateTo, duplicateFrom
	}
	duplicate := Relationship{Type: RelationshipDuplicates, FromKind: NodeFinding, From: duplicateFrom, ToKind: NodeFinding, To: duplicateTo, Comparison: &ComparisonBasis{Kind: "finding", Subject: "network"}}
	duplicate.ID = relationshipID(duplicate.Type, duplicate.FromKind, duplicate.From, duplicate.ToKind, duplicate.To)
	duplicates.Relationships = append(duplicates.Relationships, duplicate)
	if err := duplicates.Validate(); err == nil || !strings.Contains(err.Error(), "semantically equivalent") {
		t.Fatalf("unsupported finding duplication result: %v", err)
	}
}

func TestAddComparisonResolvesInternalIDsAndCanonicalizesEndpoints(t *testing.T) {
	r := graphReport(t)
	external := testProvenance
	external.Analyzer = "omarchy/plugin-audit"
	external.AnalyzerVersion = "pr8439-test"
	external.EvidenceSource = EvidenceSourceOmarchyAudit
	r.EvidenceInputs = append(r.EvidenceInputs, EvidenceInput{ID: "input-omarchy", Type: EvidenceInputOmarchyAudit, Label: "pinned Omarchy audit", Format: "omarchy-plugin-audit", Version: "pr8439-test"})
	r.Operations = append(r.Operations, Operation{ID: "external-operation", Category: "omarchy-audit-command", Command: "curl", Scope: ScopeUnknown, Confidence: ConfidenceHigh, Evidence: Evidence{Path: "omarchy-audit.json"}, Provenance: external})
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	comparison := Comparison{Type: RelationshipCorroborates, FromKind: NodeOperation, FromID: "external-operation", ToKind: NodeOperation, ToID: "operation-1"}
	if err := r.AddComparison(comparison); err != nil {
		t.Fatal(err)
	}
	if err := r.AddComparison(comparison); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, relationship := range r.Relationships {
		if relationship.Type == RelationshipCorroborates {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("comparison count = %d: %#v", count, r.Relationships)
	}
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("generated comparison rejected: %v", err)
	}
	if err := r.AddComparison(Comparison{Type: RelationshipCorroborates, FromKind: NodeOperation, FromID: "missing", ToKind: NodeOperation, ToID: "operation-1"}); err == nil {
		t.Fatal("missing comparison endpoint accepted")
	}
}

func TestDuplicatesRequireEquivalentPayloadWithinOneAnalyzerBoundary(t *testing.T) {
	r := graphReport(t)
	repeated := r.Operations[0]
	repeated.ID, repeated.Reference = "operation-repeat", ""
	r.Operations = append(r.Operations, repeated)
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	if err := r.AddComparison(Comparison{Type: RelationshipDuplicates, FromKind: NodeOperation, FromID: "operation-1", ToKind: NodeOperation, ToID: "operation-repeat"}); err != nil {
		t.Fatal(err)
	}
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("equivalent duplicate rejected: %v", err)
	}
	changed := r
	changed.Operations = append([]Operation(nil), r.Operations...)
	changed.Operations[1].Arguments = []string{"different"}
	if err := changed.Validate(); err == nil || !strings.Contains(err.Error(), "semantically equivalent") {
		t.Fatalf("different payload duplicate result = %v", err)
	}
}

func TestDisagreementRequiresTypedCoverageDifferenceShape(t *testing.T) {
	r := graphReport(t)
	external := testProvenance
	external.Analyzer = "omarchy/plugin-audit"
	external.AnalyzerVersion = "pr8439-test"
	external.EvidenceSource = EvidenceSourceOmarchyAudit
	r.EvidenceInputs = append(r.EvidenceInputs, EvidenceInput{ID: "input-omarchy", Type: EvidenceInputOmarchyAudit, Label: "pinned audit", Format: "omarchy-plugin-audit", Version: "pr8439-test"})
	r.Operations = append(r.Operations, Operation{ID: "external-command", Category: "omarchy-audit-command", Command: "wget", Scope: ScopeUnknown, Confidence: ConfidenceHigh, Evidence: Evidence{Path: "omarchy-audit.json"}, Provenance: external})
	r.Findings = append(r.Findings, Finding{ID: "coverage-difference", Claim: ClaimFact, Severity: SeverityInformational, Confidence: ConfidenceHigh, Category: "omarchy-audit-coverage-disagreement", Scope: ScopeUnknown, Title: "Coverage differs", Explanation: "Only one producer retained this semantic subject.", Evidence: []Evidence{{Path: "plugin.sh"}}, Related: []string{}, Provenance: testProvenance})
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	basis := ComparisonBasis{Kind: "coverage", Subject: "command\x00wget"}
	if err := r.AddComparison(Comparison{Type: RelationshipDisagreesWith, FromKind: NodeOperation, FromID: "external-command", ToKind: NodeFinding, ToID: "coverage-difference", Basis: basis}); err != nil {
		t.Fatal(err)
	}
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("typed coverage disagreement rejected: %v", err)
	}
	bad := r
	bad.Relationships = append([]Relationship(nil), r.Relationships...)
	for index := range bad.Relationships {
		if bad.Relationships[index].Type == RelationshipDisagreesWith {
			bad.Relationships[index].Comparison = &ComparisonBasis{Kind: "coverage", Subject: "command\x00curl"}
		}
	}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "coverage-difference") {
		t.Fatalf("unrelated disagreement result = %v", err)
	}
}

func TestSchemaOneReportFailsClosedAfterEvidenceGraphMigration(t *testing.T) {
	data := []byte(`{"schemaVersion":"1.0.0"}`)
	if _, err := Decode(data); err == nil || !strings.Contains(err.Error(), "unsupported report schema") {
		t.Fatalf("legacy schema error = %v", err)
	}
}
