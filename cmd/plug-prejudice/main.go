package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/analyze"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/inventory"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/policy"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

const (
	version       = "0.0.0-dev"
	policyVersion = "deterministic-v1"
)

func main() {
	os.Exit(run())
}

func run() int {
	flags := flag.NewFlagSet("plug-prejudice", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	target := flags.String("target", "", "plugin directory to inspect as hostile input")
	displayName := flags.String("display-name", "", "trusted display label supplied by the containment broker")
	sandboxed := flags.Bool("sandboxed", false, "record that a trusted broker established containment")
	resourceLimited := flags.Bool("resource-limited", false, "record that the trusted broker established resource containment")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if *target == "" || flags.NArg() != 0 {
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
		fmt.Fprintf(os.Stderr, "scan target: %v\n", err)
		return 1
	}
	analysis := analyze.Sources(result.Contents)
	analyze.Inventory(result.Files, result.Contents, &analysis)
	limitations := append(result.Limitations, analysis.Limitations...)
	status := report.StatusComplete
	if len(result.Errors) > 0 || len(limitations) > 0 {
		status = report.StatusIncomplete
	}
	r := report.Report{
		SchemaVersion: report.SchemaVersion,
		Status:        status,
		Scan: report.ScanMetadata{
			ScannerVersion: version,
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
		Inventory:   nonNil(result.Files),
		Operations:  nonNil(analysis.Operations),
		Resources:   nonNil(analysis.Resources),
		Findings:    nonNil(analysis.Findings),
		Limitations: nonNil(limitations),
		Errors:      nonNil(result.Errors),
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(true)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(r); err != nil {
		fmt.Fprintf(os.Stderr, "encode report: %v\n", err)
		return 1
	}
	return 0
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
