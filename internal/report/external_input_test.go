package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

const (
	syntheticSubjectFormat  = "synthetic-subject-bound-audit"
	syntheticSubjectVersion = "future-test-v1"
)

func appendExternalBindingUnknown(r *Report, inputID string) {
	r.Status = StatusIncomplete
	r.Unknowns = append(r.Unknowns, Unknown{
		ID: "unknown-binding-" + inputID, Category: ExternalEvidenceBindingCategory,
		Reason: UnknownExternalBinding, Scope: ScopeUnknown, Confidence: ConfidenceHigh,
		Title:       "External input is not target-snapshot bound",
		Description: "The external document does not identify the retained target snapshot.",
		Evidence:    []Evidence{{InputID: inputID, Path: "omarchy-audit.json"}}, Origins: []ValueOrigin{},
		AffectedOperations: []string{}, SuppressedRules: []string{ExternalSnapshotBindingRule},
		Provenance: Provenance{RuleID: ExternalBindingAssessmentRule, Analyzer: DeterministicAnalyzer, AnalyzerVersion: r.Scan.ScannerVersion, EvidenceSource: EvidenceSourceOmarchyAudit},
	})
	if err := r.BuildEvidenceGraph(); err != nil {
		panic(err)
	}
	if err := r.BuildReviewSummary(coverageFromInventory(r.Inventory)); err != nil {
		panic(err)
	}
}

func syntheticSubjectPolicies() []externalEvidenceInputPolicy {
	policies := append([]externalEvidenceInputPolicy(nil), supportedExternalEvidenceInputPolicies[:]...)
	return append(policies, externalEvidenceInputPolicy{
		Type: EvidenceInputOmarchyAudit, Format: syntheticSubjectFormat, Version: syntheticSubjectVersion,
		RequiresDocumentSHA256: true, SuppliesSubjectRootDigest: true,
	})
}

func syntheticSubjectInput(t *testing.T, subject string) EvidenceInput {
	t.Helper()
	document, err := json.Marshal(struct {
		SubjectRootDigest string `json:"subjectRootDigest"`
	}{SubjectRootDigest: subject})
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		SubjectRootDigest string `json:"subjectRootDigest"`
	}
	if err := json.Unmarshal(document, &parsed); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(document)
	return EvidenceInput{
		ID: "input-future", Type: EvidenceInputOmarchyAudit, Label: "synthetic future audit",
		DocumentSHA256: hex.EncodeToString(digest[:]), SubjectRootDigest: parsed.SubjectRootDigest,
		Format: syntheticSubjectFormat, Version: syntheticSubjectVersion,
	}
}

func TestCurrentOmarchyDocumentDigestNeverEstablishesSubjectBinding(t *testing.T) {
	document := []byte(`{"plugin":"different-target"}`)
	tests := []struct {
		name   string
		mutate func(*Report, *EvidenceInput)
	}{
		{name: "document-digest", mutate: func(_ *Report, _ *EvidenceInput) {}},
		{name: "document-digest-equals-target-root", mutate: func(r *Report, input *EvidenceInput) {
			input.DocumentSHA256 = r.Target.RootDigest
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := validReport()
			input := NewOmarchyAuditEvidenceInput("input-omarchy", "audit", document)
			test.mutate(&r, &input)
			r.EvidenceInputs = append(r.EvidenceInputs, input)
			if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "binding unknown") {
				t.Fatalf("snapshot-unbound document result = %v", err)
			}
		})
	}
}

func TestCurrentOmarchyFormatRejectsSubjectRootDigest(t *testing.T) {
	r := validReport()
	input := NewOmarchyAuditEvidenceInput("input-omarchy", "audit", []byte(`{"plugin":"example"}`))
	input.SubjectRootDigest = r.Target.RootDigest
	r.EvidenceInputs = append(r.EvidenceInputs, input)
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "does not supply") {
		t.Fatalf("current-format subject digest result = %v", err)
	}
}

func TestExternalFormatPolicyCannotBeProducerSelected(t *testing.T) {
	r := validReport()
	input := NewOmarchyAuditEvidenceInput("input-omarchy", "audit", []byte(`{"subjectRootDigest":"forged"}`))
	input.Format = "producer-selected-subject-format"
	input.Version = "1"
	input.SubjectRootDigest = r.Target.RootDigest
	r.EvidenceInputs = append(r.EvidenceInputs, input)
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("producer-selected subject format result = %v", err)
	}
}

func TestCurrentOmarchyFormatRequiresCalculatedDocumentDigest(t *testing.T) {
	r := validReport()
	r.EvidenceInputs = append(r.EvidenceInputs, EvidenceInput{
		ID: "input-omarchy", Type: EvidenceInputOmarchyAudit, Label: "audit",
		Format: OmarchyAuditInputFormat, Version: OmarchyAuditInputVersion,
	})
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "requires a document SHA-256") {
		t.Fatalf("missing document digest result = %v", err)
	}
}

func TestSupportedSubjectRootDigestMustMatchTarget(t *testing.T) {
	r := validReport()
	r.EvidenceInputs = append(r.EvidenceInputs, syntheticSubjectInput(t, strings.Repeat("a", 64)))
	if err := r.validateWithEvidenceInputPolicies(syntheticSubjectPolicies()); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched supported subject digest result = %v", err)
	}
}

func TestExternalDigestSyntax(t *testing.T) {
	t.Run("document", func(t *testing.T) {
		r := validReport()
		input := NewOmarchyAuditEvidenceInput("input-omarchy", "audit", []byte(`{}`))
		input.DocumentSHA256 = "ABC"
		r.EvidenceInputs = append(r.EvidenceInputs, input)
		if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "document SHA-256") {
			t.Fatalf("malformed document digest result = %v", err)
		}
	})
	t.Run("subject", func(t *testing.T) {
		r := validReport()
		input := syntheticSubjectInput(t, "ABC")
		r.EvidenceInputs = append(r.EvidenceInputs, input)
		if err := r.validateWithEvidenceInputPolicies(syntheticSubjectPolicies()); err == nil || !strings.Contains(err.Error(), "subject root digest") {
			t.Fatalf("malformed subject digest result = %v", err)
		}
	})
}

func TestCurrentOmarchyDocumentDigestWithBindingUnknown(t *testing.T) {
	document := []byte(`{"commands":["curl"]}`)
	want := sha256.Sum256(document)
	r := validReport()
	input := NewOmarchyAuditEvidenceInput("input-omarchy", "audit", document)
	if input.DocumentSHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("document SHA-256 = %q, want %x", input.DocumentSHA256, want)
	}
	r.EvidenceInputs = append(r.EvidenceInputs, input)
	appendExternalBindingUnknown(&r, input.ID)
	if err := r.Validate(); err != nil {
		t.Fatalf("document-bound, snapshot-unbound input rejected: %v", err)
	}
	if r.Status != StatusIncomplete {
		t.Fatalf("snapshot-unbound current Omarchy report status = %q", r.Status)
	}
	encoded, err := EncodeCanonical(r)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var decodedInput EvidenceInput
	for _, candidate := range decoded.EvidenceInputs {
		if candidate.ID == input.ID {
			decodedInput = candidate
		}
	}
	if decodedInput.DocumentSHA256 != input.DocumentSHA256 || decodedInput.SubjectRootDigest != "" || decoded.Status != StatusIncomplete {
		t.Fatalf("canonical external-input round trip changed binding semantics: %#v", decodedInput)
	}
}

func TestSyntheticSupportedSubjectDigestBindsMatchingTarget(t *testing.T) {
	r := validReport()
	r.EvidenceInputs = append(r.EvidenceInputs, syntheticSubjectInput(t, r.Target.RootDigest))
	if err := r.validateWithEvidenceInputPolicies(syntheticSubjectPolicies()); err != nil {
		t.Fatalf("matching supported subject digest rejected: %v", err)
	}
}

func TestExternalDocumentDigestTracksExactBytes(t *testing.T) {
	first := NewOmarchyAuditEvidenceInput("input-omarchy", "audit", []byte(`{"commands":["curl"]}`))
	second := NewOmarchyAuditEvidenceInput("input-omarchy", "audit", []byte(`{"commands":["wget"]}`))
	if first.DocumentSHA256 == second.DocumentSHA256 {
		t.Fatalf("different pinned documents shared digest %q", first.DocumentSHA256)
	}
	if first.SubjectRootDigest != "" || second.SubjectRootDigest != "" {
		t.Fatal("current Omarchy document hashing fabricated a subject root digest")
	}
}

func TestChangingOnlyDocumentDigestDoesNotChangeSubjectBinding(t *testing.T) {
	unbound := validReport()
	unbound.EvidenceInputs = append(unbound.EvidenceInputs, NewOmarchyAuditEvidenceInput("input-omarchy", "audit", []byte(`{"commands":["curl"]}`)))
	firstErr := unbound.Validate()
	unbound.EvidenceInputs[1].DocumentSHA256 = strings.Repeat("b", 64)
	secondErr := unbound.Validate()
	for index, err := range []error{firstErr, secondErr} {
		if err == nil || !strings.Contains(err.Error(), "binding unknown") {
			t.Fatalf("unbound document variant %d result = %v", index, err)
		}
	}

	boundUnknown := validReport()
	boundUnknown.EvidenceInputs = append(boundUnknown.EvidenceInputs, NewOmarchyAuditEvidenceInput("input-omarchy", "audit", []byte(`{"commands":["curl"]}`)))
	appendExternalBindingUnknown(&boundUnknown, "input-omarchy")
	if err := boundUnknown.Validate(); err != nil {
		t.Fatal(err)
	}
	boundUnknown.EvidenceInputs[1].DocumentSHA256 = strings.Repeat("c", 64)
	if err := boundUnknown.Validate(); err != nil {
		t.Fatalf("changed document identity altered snapshot-binding status: %v", err)
	}
}
