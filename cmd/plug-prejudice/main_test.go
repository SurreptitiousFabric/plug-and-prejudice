package main

import "testing"

func TestTargetDisplayNamePrefersBrokerLabel(t *testing.T) {
	if got := targetDisplayName("/target", "org.example.plugin"); got != "org.example.plugin" {
		t.Fatalf("targetDisplayName() = %q", got)
	}
	if got := targetDisplayName("/tmp/example", ""); got != "example" {
		t.Fatalf("targetDisplayName() fallback = %q", got)
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
