package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validReport() Report {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	return Report{
		SchemaVersion: SchemaVersion,
		Status:        StatusComplete,
		Scan: ScanMetadata{ScannerVersion: "test", PolicyVersion: "test", StartedAt: now, CompletedAt: now, Sandboxed: true,
			ResourceLimits: &ResourceLimits{MemoryMaxBytes: 256 << 20, TasksMax: 64, CPUQuotaPercent: 100, WallTimeSeconds: 30}},
		Target:    Target{DisplayName: "example", FileCount: 1},
		Inventory: []File{}, Operations: []Operation{}, Resources: []Resource{}, Findings: []Finding{}, Limitations: []Limitation{}, Errors: []ScanError{},
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
		Category: "execution", Scope: ScopeRuntime, Title: "Example", Explanation: "Example", Provenance: "test",
		Evidence: []Evidence{{Path: "../outside", LineStart: 1}}, Related: []string{"missing"},
	}}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "unsafe evidence path") {
		t.Fatalf("Validate() error = %v", err)
	}
	r.Findings[0].Evidence[0].Path = "plugin.sh"
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "missing operation") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestCompleteReportCannotHideLimitations(t *testing.T) {
	r := validReport()
	r.Limitations = []Limitation{{Code: "unknown", Description: "Not inspected"}}
	if err := r.Validate(); err == nil {
		t.Fatal("complete report with limitation was accepted")
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
