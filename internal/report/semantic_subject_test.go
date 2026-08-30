package report

import (
	"strings"
	"testing"
)

func resourceSubjectReport(t *testing.T, first, second Resource) Report {
	t.Helper()
	r := graphReport(t)
	external := appendTestExternalInput(&r, "input-omarchy")
	r.Operations = append(r.Operations, Operation{ID: "external-operation", Category: "omarchy-command", Command: "read", Arguments: []string{}, Scope: ScopeUnknown, Confidence: ConfidenceHigh, Evidence: Evidence{InputID: "input-omarchy", Path: "audit.json"}, Provenance: external})
	first.ID, first.RelatedOperationID, first.Evidence, first.Provenance = "resource-first", r.Operations[0].ID, r.Operations[0].Evidence, testProvenance
	second.ID, second.RelatedOperationID, second.Evidence, second.Provenance = "resource-second", "external-operation", Evidence{InputID: "input-omarchy", Path: "audit.json"}, external
	if first.Scope == "" {
		first.Scope = ScopeRuntime
	}
	if second.Scope == "" {
		second.Scope = ScopeUnknown
	}
	if first.Confidence == "" {
		first.Confidence = ConfidenceHigh
	}
	if second.Confidence == "" {
		second.Confidence = ConfidenceHigh
	}
	r.Resources = []Resource{first, second}
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestResourceComparisonSubjectRejectsNULDelimiterCollision(t *testing.T) {
	first := Resource{Kind: "filesystem-path", Access: "read\x00special", Value: "x"}
	second := Resource{Kind: "filesystem-path", Access: "read", Value: "special\x00x"}
	r := resourceSubjectReport(t, first, second)
	firstSubject, _ := r.semanticSubject(NodeResource, "resource-first")
	secondSubject, _ := r.semanticSubject(NodeResource, "resource-second")
	if firstSubject == secondSubject {
		t.Fatalf("distinct resource triples share subject %q", firstSubject)
	}
	if err := r.AddComparison(Comparison{Type: RelationshipCorroborates, FromKind: NodeResource, FromID: "resource-first", ToKind: NodeResource, ToID: "resource-second"}); err == nil {
		t.Fatal("distinct NUL-containing resource triples corroborated")
	}
}

func TestResourceComparisonSubjectIsInjectiveForHostileFieldSamples(t *testing.T) {
	values := []string{"", "x", "\x00", ":", "1:x", "read\x00special", "special\x00x", "prefix", "prefixsuffix", "é", "界", "\\u0000", "\n\t"}
	type triple struct{ kind, access, value string }
	seen := make(map[string]triple, len(values)*len(values)*len(values))
	for _, kind := range values {
		for _, access := range values {
			for _, value := range values {
				current := triple{kind, access, value}
				subject := resourceComparisonSubject(kind, access, value)
				if previous, exists := seen[subject]; exists && previous != current {
					t.Fatalf("subject collision: %#v and %#v -> %q", previous, current, subject)
				}
				seen[subject] = current
			}
		}
	}
}

func TestResourceComparisonSubjectUsesExactlyKindAccessValue(t *testing.T) {
	base := Resource{Kind: "network-host", Access: "connect", Value: "example.test", Sensitive: false, Dynamic: false, Scope: ScopeRuntime, Confidence: ConfidenceHigh}
	want := resourceComparisonSubject(base.Kind, base.Access, base.Value)
	changed := base
	changed.Sensitive, changed.Dynamic, changed.Scope, changed.Confidence = true, true, ScopeTooling, ConfidenceLow
	if got := resourceComparisonSubject(changed.Kind, changed.Access, changed.Value); got != want {
		t.Fatalf("non-subject fields changed identity: %q != %q", got, want)
	}
	for _, mutation := range []struct {
		name     string
		resource Resource
	}{
		{"kind", Resource{Kind: base.Kind + "x", Access: base.Access, Value: base.Value}},
		{"access", Resource{Kind: base.Kind, Access: base.Access + "x", Value: base.Value}},
		{"value", Resource{Kind: base.Kind, Access: base.Access, Value: base.Value + "x"}},
	} {
		if got := resourceComparisonSubject(mutation.resource.Kind, mutation.resource.Access, mutation.resource.Value); got == want {
			t.Fatalf("%s change retained subject", mutation.name)
		}
	}
}

func TestResourceComparisonSubjectProducerValidatorRoundTrip(t *testing.T) {
	resource := Resource{Kind: "filesystem\x00path", Access: "read:write\x00", Value: "é/界\x00value"}
	r := resourceSubjectReport(t, resource, resource)
	if err := r.AddComparison(Comparison{Type: RelationshipCorroborates, FromKind: NodeResource, FromID: "resource-first", ToKind: NodeResource, ToID: "resource-second"}); err != nil {
		t.Fatal(err)
	}
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	want := resourceComparisonSubject(resource.Kind, resource.Access, resource.Value)
	var basis *ComparisonBasis
	for i := range r.Relationships {
		if r.Relationships[i].Type == RelationshipCorroborates {
			basis = r.Relationships[i].Comparison
		}
	}
	if basis == nil || basis.Kind != string(NodeResource) || basis.Subject != want {
		t.Fatalf("comparison basis = %#v, want %q", basis, want)
	}
	encoded, err := EncodeCanonical(r)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for i := range decoded.Relationships {
		if decoded.Relationships[i].Type == RelationshipCorroborates {
			if decoded.Relationships[i].Comparison == nil || decoded.Relationships[i].Comparison.Subject != want {
				t.Fatalf("round-trip basis = %#v", decoded.Relationships[i].Comparison)
			}
			return
		}
	}
	t.Fatal("corroboration missing after round trip")
}

func TestDistinctNULResourcesRemainARealCoverageDifference(t *testing.T) {
	first := Resource{Kind: "filesystem-path", Access: "read\x00special", Value: "x"}
	second := Resource{Kind: "filesystem-path", Access: "read", Value: "special\x00x"}
	r := resourceSubjectReport(t, first, second)
	r.Findings = append(r.Findings, Finding{ID: "coverage-resource", Claim: ClaimFact, Severity: SeverityInformational, Confidence: ConfidenceHigh, Category: CoverageDifferenceCategory, Scope: ScopeUnknown, Title: "Resource coverage differs", Explanation: "Only the local source retained this exact resource triple.", Evidence: []Evidence{r.Resources[0].Evidence}, Related: []string{}, Provenance: Provenance{RuleID: CoverageComparisonRule, Analyzer: DeterministicAnalyzer, AnalyzerVersion: r.Scan.ScannerVersion, EvidenceSource: EvidenceSourceTargetSource}})
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	subject, ok := r.semanticSubject(NodeResource, "resource-first")
	if !ok {
		t.Fatal("local resource subject missing")
	}
	if err := r.AddComparison(Comparison{Type: RelationshipDisagreesWith, FromKind: NodeResource, FromID: "resource-first", ToKind: NodeFinding, ToID: "coverage-resource", Basis: ComparisonBasis{Kind: "coverage", Subject: subject}}); err != nil {
		t.Fatal(err)
	}
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("distinct NUL resources were conflated: %v", err)
	}
}

func TestValidatorRejectsLegacyDelimiterResourceSubject(t *testing.T) {
	resource := Resource{Kind: "filesystem-path", Access: "read", Value: "target"}
	r := resourceSubjectReport(t, resource, resource)
	if err := r.AddComparison(Comparison{Type: RelationshipCorroborates, FromKind: NodeResource, FromID: "resource-first", ToKind: NodeResource, ToID: "resource-second"}); err != nil {
		t.Fatal(err)
	}
	for i := range r.Relationships {
		if r.Relationships[i].Type == RelationshipCorroborates {
			r.Relationships[i].Comparison.Subject = resource.Kind + "\x00" + resource.Access + "\x00" + resource.Value
		}
	}
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "semantic subject") {
		t.Fatalf("legacy delimiter subject result = %v", err)
	}
}

func TestOperationComparisonSubjectRemainsUnchanged(t *testing.T) {
	r := graphReport(t)
	got, ok := r.semanticSubject(NodeOperation, r.Operations[0].ID)
	if !ok || got != "command\x00curl" {
		t.Fatalf("operation subject = %q, %v", got, ok)
	}
}
