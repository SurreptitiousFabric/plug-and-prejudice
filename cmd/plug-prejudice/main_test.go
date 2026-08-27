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
