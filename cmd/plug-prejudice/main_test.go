package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/analyze"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/buildinfo"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/omarchyaudit"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestTargetDisplayNamePrefersBrokerLabel(t *testing.T) {
	if got := targetDisplayName("/target", "org.example.plugin"); got != "org.example.plugin" {
		t.Fatalf("targetDisplayName() = %q", got)
	}
	if got := targetDisplayName("/tmp/example", ""); got != "example" {
		t.Fatalf("targetDisplayName() fallback = %q", got)
	}
}

func TestWriteVersionIsMachineReadable(t *testing.T) {
	var output bytes.Buffer
	if err := writeVersion(&output); err != nil {
		t.Fatal(err)
	}
	var got struct {
		ReviewerVersion string `json:"reviewerVersion"`
	}
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatalf("decode version: %v", err)
	}
	if got.ReviewerVersion != buildinfo.Version {
		t.Fatalf("version = %q, want %q", got.ReviewerVersion, buildinfo.Version)
	}
}

func TestIngestOmarchyAuditFileRequiresMatchingManifestIdentity(t *testing.T) {
	audit := omarchyaudit.Report{ID: "example.plugin", Declared: omarchyaudit.Declared{Commands: []string{}, Network: []string{}, Reads: []string{}, Writes: []string{}}, Observed: omarchyaudit.Observed{Commands: []omarchyaudit.Command{}, Network: []omarchyaudit.Host{}, Reads: []omarchyaudit.Path{}, Writes: []omarchyaudit.Path{}}, Risks: []omarchyaudit.Risk{}, Verdict: omarchyaudit.Verdict{Level: "minimal", Reasons: []string{}}}
	data, err := json.Marshal(audit)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	analysis := analyze.Result{}
	if _, err := ingestOmarchyAuditFile(path, omarchyaudit.FormatPR8439Revision732b104, &report.Manifest{ID: "different.plugin"}, &analysis); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("identity mismatch error = %v", err)
	}
	if comparisons, err := ingestOmarchyAuditFile(path, omarchyaudit.FormatPR8439Revision732b104, &report.Manifest{ID: "example.plugin"}, &analysis); err != nil || comparisons == nil {
		t.Fatalf("matching audit = %#v, %v", comparisons, err)
	}
}

func TestImportedAuditComparisonsProduceValidReportGraph(t *testing.T) {
	analysis := analyze.Sources(map[string][]byte{
		"manifest.json": []byte(`{"schemaVersion":1,"id":"example.plugin","name":"Example","version":"1.0.0","kinds":["panel"],"entryPoints":{"panel":"Panel.qml"}}`),
		"plugin.sh":     []byte("#!/bin/sh\ncurl https://same.example.test\n"),
	})
	audit := omarchyaudit.Report{ID: "example.plugin", Declared: omarchyaudit.Declared{Commands: []string{}, Network: []string{}, Reads: []string{}, Writes: []string{}}, Observed: omarchyaudit.Observed{Commands: []omarchyaudit.Command{{Name: "curl"}}, Network: []omarchyaudit.Host{{Host: "same.example.test"}, {Host: "external.example.test"}}, Reads: []omarchyaudit.Path{}, Writes: []omarchyaudit.Path{}}, Risks: []omarchyaudit.Risk{}, Summary: omarchyaudit.Summary{UndeclaredCommands: 1, UndeclaredNetwork: 2}, Verdict: omarchyaudit.Verdict{Level: "moderate", Reasons: []string{}}}
	data, _ := json.Marshal(audit)
	path := filepath.Join(t.TempDir(), "audit.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	comparisons, err := ingestOmarchyAuditFile(path, omarchyaudit.FormatPR8439Revision732b104, analysis.Manifest, &analysis)
	if err != nil {
		t.Fatal(err)
	}
	r := validCommandReport()
	r.Target.Manifest = analysis.Manifest
	r.Operations = nonNil(analysis.Operations)
	r.Resources = nonNil(analysis.Resources)
	r.Findings = nonNil(analysis.Findings)
	r.Unknowns = nonNil(analysis.Unknowns)
	r.Limitations = nonNil(analysis.Limitations)
	if len(r.Unknowns) > 0 || len(r.Limitations) > 0 {
		r.Status = report.StatusIncomplete
	}
	if err := r.BuildEvidenceGraph(); err != nil {
		t.Fatal(err)
	}
	for _, comparison := range comparisons {
		if err := r.AddComparison(comparison); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("merged report invalid: %v", err)
	}
	found := false
	for _, relationship := range r.Relationships {
		if relationship.Type == report.RelationshipCorroborates {
			found = true
		}
	}
	if !found {
		t.Fatalf("corroboration missing: %#v", r.Relationships)
	}
}

func TestScanResourceLimitsReflectPolicy(t *testing.T) {
	if scanResourceLimits(false) != nil {
		t.Fatal("unsandboxed scan received resource metadata")
	}
	limits := scanResourceLimits(true)
	if limits == nil || limits.MemoryMaxBytes != 256<<20 || limits.TasksMax != 64 || limits.CPUQuotaPercent != 100 || limits.WallTimeSeconds != 30 {
		t.Fatalf("unexpected resource metadata: %#v", limits)
	}
}

func TestWriteReportValidatesBeforeWriting(t *testing.T) {
	var output bytes.Buffer
	invalid := validCommandReport()
	invalid.Status = report.StatusIncomplete
	if err := writeReport(&output, invalid); err == nil || !strings.Contains(err.Error(), "validate report") {
		t.Fatalf("writeReport() error = %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("invalid report wrote %d bytes", output.Len())
	}
}

func TestScannerDiagnosticIsSanitizedAndBounded(t *testing.T) {
	hostile := "before\x1b[31m\u202e" + strings.Repeat("x", maxScannerDiagnosticBytes*2)
	got := scannerDiagnostic("scan target", errors.New(hostile))
	if len(got) != maxScannerDiagnosticBytes || strings.ContainsAny(got, "\x1b\u202e") || !strings.HasSuffix(got, "...[truncated]") {
		t.Fatalf("scanner diagnostic boundary failed: %d bytes, %q", len(got), got[:min(len(got), 80)])
	}
}

func TestWriteReportEmitsStrictlyDecodableJSON(t *testing.T) {
	var output bytes.Buffer
	if err := writeReport(&output, validCommandReport()); err != nil {
		t.Fatalf("writeReport(): %v", err)
	}
	decoded, err := report.Decode(output.Bytes())
	if err != nil {
		t.Fatalf("strictly decode emitted report: %v", err)
	}
	if decoded.Status != report.StatusComplete {
		t.Fatalf("decoded status = %q", decoded.Status)
	}
}

func validCommandReport() report.Report {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	r := report.Report{
		SchemaVersion: report.SchemaVersion,
		Status:        report.StatusComplete,
		Scan: report.ScanMetadata{
			ScannerVersion: buildinfo.Version,
			PolicyVersion:  policyVersion,
			StartedAt:      now,
			CompletedAt:    now,
		},
		Target:        report.Target{DisplayName: "fixture"},
		Inventory:     []report.File{},
		Operations:    []report.Operation{},
		Resources:     []report.Resource{},
		Findings:      []report.Finding{},
		Unknowns:      []report.Unknown{},
		Relationships: []report.Relationship{},
		Limitations:   []report.Limitation{},
		Errors:        []report.ScanError{},
	}
	if err := r.BuildReviewSummary(report.NewCoverageSummary(0, 0, 0)); err != nil {
		panic(err)
	}
	return r
}
