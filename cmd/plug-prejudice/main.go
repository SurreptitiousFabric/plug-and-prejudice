package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/analyze"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/buildinfo"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/inventory"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/omarchyaudit"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/policy"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/safetext"
)

const (
	policyVersion             = "deterministic-v1"
	maxScannerDiagnosticBytes = 4 << 10
)

func main() {
	os.Exit(run())
}

func run() int {
	flags := flag.NewFlagSet("plug-prejudice", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	target := flags.String("target", "", "plugin directory to inspect as hostile input")
	displayName := flags.String("display-name", "", "trusted display label supplied by the containment broker")
	sandboxed := flags.Bool("sandboxed", false, "record that a trusted broker established containment")
	resourceLimited := flags.Bool("resource-limited", false, "record that the trusted broker established resource containment")
	omarchyAuditPath := flags.String("omarchy-audit", "", "optional local Omarchy plugin-audit JSON file")
	omarchyAuditFormat := flags.String("omarchy-audit-format", "", "required pinned format identifier for --omarchy-audit")
	version := flags.Bool("version", false, "print machine-readable scanner version")
	if err := flags.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, "usage: plug-prejudice --target DIRECTORY [--sandboxed]")
			return 0
		}
		writeScannerDiagnostic("parse arguments", err)
		return 2
	}
	if *version {
		if flags.NArg() != 0 || *target != "" || *displayName != "" || *sandboxed || *resourceLimited || *omarchyAuditPath != "" || *omarchyAuditFormat != "" {
			fmt.Fprintln(os.Stderr, "--version cannot be combined with scan arguments")
			return 2
		}
		if err := writeVersion(os.Stdout); err != nil {
			writeScannerDiagnostic("write version", err)
			return 1
		}
		return 0
	}
	if *target == "" || flags.NArg() != 0 || ((*omarchyAuditPath == "") != (*omarchyAuditFormat == "")) {
		fmt.Fprintln(os.Stderr, "usage: plug-prejudice --target DIRECTORY [--sandboxed]")
		return 2
	}
	if *sandboxed != *resourceLimited {
		fmt.Fprintln(os.Stderr, "sandbox and resource containment must be established together")
		return 2
	}

	started := time.Now().UTC()
	result, err := inventory.Scan(*target, inventory.DefaultLimits())
	if err != nil {
		writeScannerDiagnostic("scan target", err)
		return 1
	}
	analysis := analyze.Sources(result.Contents)
	analyze.Inventory(result.Files, result.Contents, &analysis)
	comparisons := []report.Comparison{}
	if *omarchyAuditPath != "" {
		comparisons, err = ingestOmarchyAuditFile(*omarchyAuditPath, *omarchyAuditFormat, analysis.Manifest, &analysis)
		if err != nil {
			writeScannerDiagnostic("ingest Omarchy audit", err)
			return 1
		}
	}
	limitations := append(result.Limitations, analysis.Limitations...)
	files, coverage := analyze.AssignCoverageDispositions(result.Files, result.Contents, limitations, result.Errors)
	status := report.StatusComplete
	if len(analysis.Unknowns) > 0 || len(result.Errors) > 0 || len(limitations) > 0 || coverage.ExcludedUnits > 0 || (coverage.Level != "complete" && coverage.Level != "not-applicable") {
		status = report.StatusIncomplete
	}
	r := report.Report{
		SchemaVersion: report.SchemaVersion,
		Status:        status,
		Scan: report.ScanMetadata{
			ScannerVersion: buildinfo.Version,
			PolicyVersion:  policyVersion,
			StartedAt:      started,
			CompletedAt:    time.Now().UTC(),
			Sandboxed:      *sandboxed,
			ResourceLimits: scanResourceLimits(*resourceLimited),
		},
		Target: report.Target{
			DisplayName: targetDisplayName(*target, *displayName),
			RootDigest:  result.RootDigest,
			FileCount:   len(result.Files),
			ReadBytes:   result.ReadBytes,
			BinaryBytes: result.BinaryBytes,
			Manifest:    analysis.Manifest,
		},
		EvidenceInputs: []report.EvidenceInput{{ID: report.TargetEvidenceInputID, Type: report.EvidenceInputTarget, Label: "scanned target", SubjectRootDigest: result.RootDigest, Format: report.TargetEvidenceInputFormat, Version: report.TargetEvidenceInputVersion}},
		Inventory:      nonNil(files),
		Operations:     nonNil(analysis.Operations),
		Resources:      nonNil(analysis.Resources),
		Findings:       nonNil(analysis.Findings),
		Unknowns:       nonNil(analysis.Unknowns),
		Relationships:  []report.Relationship{},
		Limitations:    nonNil(limitations),
		Errors:         nonNil(result.Errors),
	}
	if *omarchyAuditPath != "" {
		r.EvidenceInputs = append(r.EvidenceInputs, report.EvidenceInput{ID: analyze.OmarchyAuditEvidenceInputID, Type: report.EvidenceInputOmarchyAudit, Label: "pinned Omarchy audit for " + analysis.Manifest.ID, Format: report.OmarchyAuditInputFormat, Version: report.OmarchyAuditInputVersion})
	}
	if status == report.StatusIncomplete && len(r.Unknowns) == 0 && len(r.Limitations) == 0 && len(r.Errors) == 0 {
		r.Limitations = append(r.Limitations, report.Limitation{Code: "analysis-coverage-incomplete", Description: "At least one retained artifact was only partially analyzed or could not be analyzed.", Scope: report.ScopeUnknown})
	}
	if err := r.BuildEvidenceGraph(); err != nil {
		writeScannerDiagnostic("build evidence graph", err)
		return 1
	}
	for _, comparison := range comparisons {
		if err := r.AddComparison(comparison); err != nil {
			writeScannerDiagnostic("build evidence comparison", err)
			return 1
		}
	}
	if err := r.BuildReviewSummary(coverage); err != nil {
		writeScannerDiagnostic("build review summary", err)
		return 1
	}
	if err := writeReport(os.Stdout, r); err != nil {
		writeScannerDiagnostic("write report", err)
		return 1
	}
	return 0
}

func writeVersion(output io.Writer) error {
	return json.NewEncoder(output).Encode(struct {
		ReviewerVersion string `json:"reviewerVersion"`
	}{ReviewerVersion: buildinfo.Version})
}

func ingestOmarchyAuditFile(path, format string, manifest *report.Manifest, analysis *analyze.Result) ([]report.Comparison, error) {
	data, err := omarchyaudit.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	audit, err := omarchyaudit.Decode(data, format)
	if err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}
	if manifest == nil || manifest.ID == "" || audit.ID != manifest.ID {
		return nil, fmt.Errorf("audit plugin ID %q does not match parsed manifest ID", audit.ID)
	}
	return analyze.IngestOmarchyAudit(audit, analysis), nil
}

func writeScannerDiagnostic(context string, err error) {
	_, _ = fmt.Fprintln(os.Stderr, scannerDiagnostic(context, err))
}

func scannerDiagnostic(context string, err error) string {
	message := context
	if err != nil {
		message += ": " + err.Error()
	}
	return safetext.Diagnostic([]byte(message), maxScannerDiagnosticBytes)
}

func writeReport(destination io.Writer, value report.Report) error {
	if err := report.WriteCanonical(destination, value); err != nil {
		return fmt.Errorf("validate or encode report: %w", err)
	}
	return nil
}

func scanResourceLimits(established bool) *report.ResourceLimits {
	if !established {
		return nil
	}
	return &report.ResourceLimits{
		MemoryMaxBytes: policy.MemoryMaxBytes, MemorySwapBytes: policy.MemorySwapBytes,
		TasksMax: policy.TasksMax, CPUQuotaPercent: policy.CPUQuotaPercent,
		WallTimeSeconds: int(policy.WallTime.Seconds()),
	}
}

func targetDisplayName(target, supplied string) string {
	if supplied != "" {
		return supplied
	}
	return filepath.Base(filepath.Clean(target))
}

func nonNil[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}
