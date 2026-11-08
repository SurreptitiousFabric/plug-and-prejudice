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
	if len(result.Findings) != 1 || result.Findings[0].Claim != report.ClaimFact || result.Findings[0].Category != "native-binary-metadata" {
		t.Fatalf("binary metadata fact not represented: %#v", result.Findings)
	}
	if len(result.Unknowns) != 1 || result.Unknowns[0].Reason != report.UnknownNativeBehavior {
		t.Fatalf("binary uncertainty not represented: %#v", result.Unknowns)
	}
	if len(result.Limitations) != 1 || result.Limitations[0].Code != "native-binary-behavior" {
		t.Fatalf("binary limitation missing: %#v", result.Limitations)
	}
	if result.Limitations[0].Scope != report.ScopeUnknown {
		t.Fatalf("binary limitation scope missing: %#v", result.Limitations[0])
	}
}

func TestBinaryInventorySeparatesPrivilegeAndURLFactsFromBehavior(t *testing.T) {
	result := Result{}
	Inventory([]report.File{{
		Path: "bin/helper", SHA256: "abc123",
		Binary: &report.Binary{Format: "ELF", Class: "ELFCLASS64", Machine: "EM_X86_64", Libraries: []string{}, ImportedSymbols: []string{"connect"}, ExtractedStrings: []string{"https://example.test"}, EmbeddedURLs: []string{"https://example.test"}, FileCapabilities: []string{"CAP_NET_ADMIN"}, CapabilityEffective: true},
	}}, map[string][]byte{}, &result)
	if !hasFindingCategory(result, "native-privilege-metadata") || !hasFindingCategory(result, "native-url-strings") || !hasFindingCategory(result, "native-sensitive-imports") {
		t.Fatalf("ELF facts missing: %#v", result.Findings)
	}
	if len(result.Unknowns) != 1 || result.Unknowns[0].Reason != report.UnknownNativeBehavior {
		t.Fatalf("native behavior was overclaimed: %#v", result.Unknowns)
	}
}

func TestInventoryReportsPluginSymlinkWithoutFollowingIt(t *testing.T) {
	result := Result{}
	Inventory([]report.File{
		{Path: "linked-helper", Kind: "symlink", LinkTarget: "../../unrelated"},
		{Path: ".git/hooks/example", Kind: "symlink", LinkTarget: "../../ignored"},
	}, map[string][]byte{}, &result)
	if len(result.Findings) != 1 || result.Findings[0].Category != "manifest" || result.Findings[0].Evidence[0].Path != "linked-helper" ||
		result.Findings[0].Evidence[0].Operation != "symbolic link -> ../../unrelated" {
		t.Fatalf("plugin symlink finding = %#v", result.Findings)
	}
}

func TestArchiveInventorySeparatesFactsPathRiskAndUnknownPayload(t *testing.T) {
	result := Result{}
	files := []report.File{{
		Path: "payload.zip", Kind: "regular", SHA256: "abc123", Inspected: true,
		Archive: &report.Archive{Format: "zip", InventoryComplete: true, RetainedUncompressedBytes: 10, Entries: []report.ArchiveEntry{
			{Path: "safe/helper.sh", Kind: "file", Size: 5},
			{Path: "../escape", Kind: "file", Size: 5, UnsafePath: true},
		}},
	}}
	Inventory(files, map[string][]byte{"Runtime.qml": []byte("property string payload: \"payload.zip\"\n")}, &result)
	if !hasFindingCategory(result, "archive-inventory") || !hasFindingCategory(result, "archive-path-risk") {
		t.Fatalf("archive facts missing: %#v", result.Findings)
	}
	if len(result.Unknowns) != 1 || result.Unknowns[0].Reason != report.UnknownUnreachableSource || result.Unknowns[0].Scope != report.ScopeRuntime {
		t.Fatalf("archive payload unknown = %#v", result.Unknowns)
	}
	if !hasLimitationCode(result, "archive-payload-not-analyzed") || result.Limitations[len(result.Limitations)-1].Scope != report.ScopeRuntime {
		t.Fatalf("archive payload limitation = %#v", result.Limitations)
	}
}

func TestCompressedArchiveMetadataDoesNotClaimMemberInventory(t *testing.T) {
	result := Result{}
	Inventory([]report.File{{Path: "payload.gz", Kind: "regular", SHA256: "abc123", Inspected: true,
		Archive: &report.Archive{Format: "gzip", Entries: []report.ArchiveEntry{}, InventoryComplete: false}}}, map[string][]byte{}, &result)
	if !hasFindingCategory(result, "archive-inventory") || hasFindingCategory(result, "archive-path-risk") || len(result.Unknowns) != 1 {
		t.Fatalf("compressed archive conclusions = %#v", result)
	}
}
