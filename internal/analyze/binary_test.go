package analyze

import (
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestBinaryInventoryStatesBehaviorIsUnknown(t *testing.T) {
	result := Result{}
	Inventory([]report.File{{
		Path: "bin/helper-arm64", SHA256: "abc123",
		Binary: &report.Binary{Format: "ELF", Class: "ELFCLASS64", Machine: "EM_AARCH64", Libraries: []string{}},
	}}, map[string][]byte{}, &result)
	if len(result.Findings) != 1 || result.Findings[0].Claim != report.ClaimUnknown || result.Findings[0].Category != "native-binary" {
		t.Fatalf("binary uncertainty not represented: %#v", result.Findings)
	}
	if len(result.Limitations) != 1 || result.Limitations[0].Code != "native-binary-behavior" {
		t.Fatalf("binary limitation missing: %#v", result.Limitations)
	}
	if result.Limitations[0].Scope != report.ScopeUnknown {
		t.Fatalf("binary limitation scope missing: %#v", result.Limitations[0])
	}
}
