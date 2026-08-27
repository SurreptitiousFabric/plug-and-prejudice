package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/inventory"
	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

const (
	version       = "0.0.0-dev"
	policyVersion = "inventory-v1"
)

func main() {
	os.Exit(run())
}

func run() int {
	flags := flag.NewFlagSet("plug-prejudice", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	target := flags.String("target", "", "plugin directory to inspect as hostile input")
	sandboxed := flags.Bool("sandboxed", false, "record that a trusted broker established containment")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if *target == "" || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: plug-prejudice --target DIRECTORY [--sandboxed]")
		return 2
	}

	started := time.Now().UTC()
	result, err := inventory.Scan(*target, inventory.DefaultLimits())
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan target: %v\n", err)
		return 1
	}
	status := report.StatusComplete
	if len(result.Errors) > 0 || len(result.Limitations) > 0 {
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
		},
		Target: report.Target{
			DisplayName: filepath.Base(filepath.Clean(*target)),
			RootDigest:  result.RootDigest,
			FileCount:   len(result.Files),
			ReadBytes:   result.ReadBytes,
		},
		Inventory:   result.Files,
		Findings:    []report.Finding{},
		Limitations: result.Limitations,
		Errors:      result.Errors,
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
