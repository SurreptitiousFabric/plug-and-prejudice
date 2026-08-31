package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"

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

func TestScanResourceLimitsReflectPolicy(t *testing.T) {
	if scanResourceLimits(false) != nil {
		t.Fatal("unsandboxed scan received resource metadata")
	}
	limits := scanResourceLimits(true)
	if limits == nil || limits.MemoryMaxBytes != 256<<20 || limits.TasksMax != 64 || limits.CPUQuotaPercent != 100 || limits.WallTimeSeconds != 30 {
		t.Fatalf("unexpected resource metadata: %#v", limits)
	}
}
