package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
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
	if _, _, err := ingestOmarchyAuditFile(path, omarchyaudit.FormatPR8439Revision732b104, &report.Manifest{ID: "different.plugin"}, &analysis, buildinfo.Version); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("identity mismatch error = %v", err)
	}
	wantDigest := sha256.Sum256(data)
	if comparisons, input, err := ingestOmarchyAuditFile(path, omarchyaudit.FormatPR8439Revision732b104, &report.Manifest{ID: "example.plugin"}, &analysis, buildinfo.Version); err != nil || comparisons == nil || input.DocumentSHA256 != hex.EncodeToString(wantDigest[:]) || input.SubjectRootDigest != "" {
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
	comparisons, input, err := ingestOmarchyAuditFile(path, omarchyaudit.FormatPR8439Revision732b104, analysis.Manifest, &analysis, buildinfo.Version)
	if err != nil {
		t.Fatal(err)
	}
	r := validCommandReport()
	r.Inventory = []report.File{
		{Path: "manifest.json", Kind: "regular", Mode: "-rw-r--r--", Size: int64(len([]byte(`{"schemaVersion":1,"id":"example.plugin","name":"Example","version":"1.0.0","kinds":["panel"],"entryPoints":{"panel":"Panel.qml"}}`))), Inspected: true, SHA256: strings.Repeat("a", 64), ContentType: "application/json", Analysis: report.AnalysisAnalyzed},
		{Path: "plugin.sh", Kind: "regular", Mode: "-rw-r--r--", Size: int64(len([]byte("#!/bin/sh\ncurl https://same.example.test\n"))), Inspected: true, SHA256: strings.Repeat("b", 64), ContentType: "text/plain", Analysis: report.AnalysisAnalyzed},
	}
	r.Target.FileCount = 2
	r.Target.ReadBytes = r.Inventory[0].Size + r.Inventory[1].Size
	refreshCommandRootDigest(&r)
	r.EvidenceInputs = append(r.EvidenceInputs, input)
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
	if err := r.BuildReviewSummary(report.NewCoverageSummary(2, 0, 0)); err != nil {
		t.Fatal(err)
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

func TestScannerProducerEmitsIndependentlyDecodableSchemaTwoReport(t *testing.T) {
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "plugin.sh"), []byte("#!/bin/sh\ncurl https://example.test/data\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalArgs, originalStdout := os.Args, os.Stdout
	os.Args, os.Stdout = []string{"plug-prejudice", "--target", target}, writeEnd
	t.Cleanup(func() { os.Args, os.Stdout = originalArgs, originalStdout })
	done := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(readEnd)
		done <- data
	}()
	status := run()
	_ = writeEnd.Close()
	data := <-done
	_ = readEnd.Close()
	if status != 0 {
		t.Fatalf("scanner status = %d", status)
	}
	decoded, err := report.Decode(data)
	if err != nil {
		t.Fatalf("producer emitted a report rejected by the independent decoder: %v\n%s", err, data)
	}
	if decoded.SchemaVersion != report.SchemaVersion || decoded.Review == nil || decoded.Relationships == nil || decoded.Unknowns == nil {
		t.Fatalf("producer omitted schema-2 contract sections: %#v", decoded)
	}
}

func TestScannerJavaScriptProcessArgumentUncertainty(t *testing.T) {
	for _, test := range []struct {
		name, expression, suffix, prefix string
		unknown                          bool
		wantArguments                    []string
	}{
		{"computed-list", "buildArguments()", "", "", true, nil},
		{"partial-array", `["--url", runtimeURL]`, "", "", true, nil},
		{"empty-control", "[]", "", "", false, nil},
		{"literal-trailing-comment", `["https://example.test"]`, " /* note */", "", false, []string{"https://example.test"}},
		{"computed-trailing-comment", "buildArguments()", " /* note */", "", true, nil},
		{"partial-array-comments", `[/* before */ "--url", runtimeURL /* after */]`, " /* note */", "", true, nil},
		{"conditional-arguments", "args", " /* after */", "let args = ['https://discarded.example.test'];\nif (enabled) { args = chooseArguments(); }\n", true, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := t.TempDir()
			// Only the trusted producer runs. Synthetic target bytes are
			// non-executable data read through the existing test arrangement.
			contents := map[string][]byte{
				"manifest.json": []byte(`{"schemaVersion":1,"id":"example.arguments","name":"Arguments","version":"1.0.0","kinds":["service"],"entryPoints":{"service":"helper.js"}}`),
				"helper.js":     []byte("child_process.spawn('printf', ['ok']);\n" + test.prefix + "child_process.spawn('curl', " + test.expression + test.suffix + ");\n"),
			}
			for name, data := range contents {
				if err := os.WriteFile(filepath.Join(target, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			readEnd, writeEnd, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			originalArgs, originalStdout := os.Args, os.Stdout
			os.Args, os.Stdout = []string{"plug-prejudice", "--target", target}, writeEnd
			t.Cleanup(func() { os.Args, os.Stdout = originalArgs, originalStdout })
			done := make(chan []byte, 1)
			go func() {
				data, _ := io.ReadAll(readEnd)
				done <- data
			}()
			status := run()
			_ = writeEnd.Close()
			data := <-done
			_ = readEnd.Close()
			if status != 0 {
				t.Fatalf("scanner status = %d", status)
			}
			decoded, err := report.Decode(data)
			if err != nil {
				t.Fatalf("producer report rejected by independent decoder: %v", err)
			}
			var control report.Operation
			for _, op := range decoded.Operations {
				if op.Category == "process-execution-via-javascript" && op.Command == "printf" {
					control = op
				}
			}
			if control.ID == "" || control.Dynamic || control.Confidence != report.ConfidenceHigh || !reflect.DeepEqual(control.Arguments, []string{"ok"}) {
				t.Fatalf("unaffected producer control lost static evidence: %#v", control)
			}
			if !test.unknown {
				if decoded.Status != report.StatusComplete || len(decoded.Unknowns) != 0 || decoded.Review.UnknownBehavior.Unknowns != 0 {
					t.Fatalf("literal control report is incomplete: %#v", decoded)
				}
				var process report.Operation
				for _, op := range decoded.Operations {
					if op.Category == "process-execution-via-javascript" && op.Command == "curl" {
						process = op
					}
				}
				if process.ID == "" || process.Dynamic || process.Confidence != report.ConfidenceHigh || !reflect.DeepEqual(process.Arguments, test.wantArguments) {
					t.Fatalf("literal producer lost process evidence: %#v", process)
				}
				if len(test.wantArguments) > 0 {
					if len(decoded.Resources) != 1 || decoded.Resources[0].Kind != "network-domain" || decoded.Resources[0].Value != "example.test" || decoded.Resources[0].RelatedOperationID != process.ID {
						t.Fatalf("literal producer lost linked network evidence: %#v", decoded.Resources)
					}
				}
				return
			}
			if decoded.Status != report.StatusIncomplete || len(decoded.Unknowns) != 1 || decoded.Review.UnknownBehavior.Unknowns != 1 || decoded.Review.Counts.UnknownBehaviors != 1 {
				t.Fatalf("producer lost argument uncertainty: status=%s unknowns=%#v review=%#v", decoded.Status, decoded.Unknowns, decoded.Review)
			}
			unknown := decoded.Unknowns[0]
			var affected report.Operation
			for _, op := range decoded.Operations {
				if op.Command == "child_process.spawn" && op.Evidence.LineStart == 2+strings.Count(test.prefix, "\n") {
					affected = op
				}
				if op.Category == "process-execution-via-javascript" && op.Command == "curl" {
					t.Errorf("producer retained overconfident process: %#v", op)
				}
			}
			if affected.ID == "" || !affected.Dynamic || len(unknown.AffectedOperations) != 1 || unknown.AffectedOperations[0] != affected.ID ||
				unknown.Scope != report.ScopeRuntime || unknown.Provenance.RuleID != "javascript-process-arguments-unknown/v1" ||
				unknown.Evidence[0].InputID != report.TargetEvidenceInputID || unknown.Evidence[0].Operation != affected.Evidence.Operation ||
				len(unknown.Origins) == 0 || unknown.Origins[0].Evidence.Operation != test.expression || unknown.Origins[0].Evidence.InputID != report.TargetEvidenceInputID {
				t.Fatalf("producer uncertainty lost call/evidence binding: %#v; call=%#v", unknown, affected)
			}
			linked := false
			for _, edge := range decoded.Relationships {
				if edge.Type == report.RelationshipUnknownBecause && edge.From == unknown.Reference && edge.To == affected.Reference && edge.FromKind == report.NodeUnknown && edge.ToKind == report.NodeOperation {
					linked = true
				}
			}
			if !linked {
				t.Fatalf("producer graph lacks argument unknown's exact call link: %#v", decoded.Relationships)
			}
			if test.prefix != "" {
				if len(decoded.Resources) != 0 {
					t.Fatalf("discarded conditional argument still supplies resources: %#v", decoded.Resources)
				}
				found := false
				for _, origin := range unknown.Origins {
					found = found || (origin.Kind == report.OriginAssignment && origin.Name == "args" && origin.Evidence.Operation == "args = chooseArguments()")
				}
				if !found {
					t.Fatalf("producer lost conditional assignment origin: %#v", unknown.Origins)
				}
			}
		})
	}
}

func TestScannerOmarchyInputRemainsExplicitlyUnboundEndToEnd(t *testing.T) {
	target := t.TempDir()
	manifest := []byte(`{"schemaVersion":1,"id":"example.plugin","name":"Example","version":"1.0.0","kinds":["panel"],"entryPoints":{"panel":"Panel.qml"}}`)
	if err := os.WriteFile(filepath.Join(target, "manifest.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "plugin.sh"), []byte("#!/bin/sh\ncurl https://same.example.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	audit := omarchyaudit.Report{ID: "example.plugin", Declared: omarchyaudit.Declared{Commands: []string{}, Network: []string{}, Reads: []string{}, Writes: []string{}}, Observed: omarchyaudit.Observed{Commands: []omarchyaudit.Command{{Name: "curl"}}, Network: []omarchyaudit.Host{{Host: "same.example.test"}}, Reads: []omarchyaudit.Path{}, Writes: []omarchyaudit.Path{}}, Risks: []omarchyaudit.Risk{}, Summary: omarchyaudit.Summary{UndeclaredCommands: 1, UndeclaredNetwork: 1}, Verdict: omarchyaudit.Verdict{Level: "moderate", Reasons: []string{}}}
	auditBytes, err := json.Marshal(audit)
	if err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.json")
	if err := os.WriteFile(auditPath, auditBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalArgs, originalStdout := os.Args, os.Stdout
	os.Args, os.Stdout = []string{"plug-prejudice", "--target", target, "--omarchy-audit", auditPath, "--omarchy-audit-format", omarchyaudit.FormatPR8439Revision732b104}, writeEnd
	t.Cleanup(func() { os.Args, os.Stdout = originalArgs, originalStdout })
	done := make(chan []byte, 1)
	go func() { data, _ := io.ReadAll(readEnd); done <- data }()
	status := run()
	_ = writeEnd.Close()
	output := <-done
	_ = readEnd.Close()
	if status != 0 {
		t.Fatalf("scanner status = %d", status)
	}
	decoded, err := report.Decode(output)
	if err != nil {
		t.Fatalf("decode scanner output: %v\n%s", err, output)
	}
	if decoded.Status != report.StatusIncomplete {
		t.Fatalf("status = %q", decoded.Status)
	}
	foundInput, foundBindingUnknown := false, false
	wantDigest := sha256.Sum256(auditBytes)
	for _, input := range decoded.EvidenceInputs {
		if input.ID == analyze.OmarchyAuditEvidenceInputID {
			foundInput = input.DocumentSHA256 == hex.EncodeToString(wantDigest[:]) && input.SubjectRootDigest == ""
		}
	}
	for _, unknown := range decoded.Unknowns {
		if unknown.Reason == report.UnknownExternalBinding && unknown.Provenance.Analyzer == report.DeterministicAnalyzer && unknown.Provenance.EvidenceSource == report.EvidenceSourceOmarchyAudit {
			foundBindingUnknown = true
		}
	}
	if !foundInput || !foundBindingUnknown {
		t.Fatalf("external boundary missing: input=%v unknown=%v", foundInput, foundBindingUnknown)
	}
	reencoded, err := report.EncodeCanonical(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output, reencoded) {
		t.Fatal("scanner output differs from canonical decode/re-encode")
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
	if err := writeReport(&output, invalid); err == nil || !strings.Contains(err.Error(), "validate or encode report") {
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
		Target:         report.Target{DisplayName: "fixture"},
		EvidenceInputs: []report.EvidenceInput{{ID: report.TargetEvidenceInputID, Type: report.EvidenceInputTarget, Label: "test target", Format: report.TargetEvidenceInputFormat, Version: report.TargetEvidenceInputVersion}},
		Inventory:      []report.File{},
		Operations:     []report.Operation{},
		Resources:      []report.Resource{},
		Findings:       []report.Finding{},
		Unknowns:       []report.Unknown{},
		Relationships:  []report.Relationship{},
		Limitations:    []report.Limitation{},
		Errors:         []report.ScanError{},
	}
	refreshCommandRootDigest(&r)
	if err := r.BuildReviewSummary(report.NewCoverageSummary(0, 0, 0)); err != nil {
		panic(err)
	}
	return r
}

func refreshCommandRootDigest(r *report.Report) {
	digest, err := report.InventoryRootDigest(r.Inventory)
	if err != nil {
		panic(err)
	}
	r.Target.RootDigest = digest
	for index := range r.EvidenceInputs {
		if r.EvidenceInputs[index].ID == report.TargetEvidenceInputID {
			r.EvidenceInputs[index].SubjectRootDigest = digest
		}
	}
}
