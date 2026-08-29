package inventory

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func FuzzScanRegularBytesNeverPanics(f *testing.F) {
	for _, seed := range [][]byte{
		{},
		[]byte("plain text\n"),
		{0x7f, 'E', 'L', 'F', 0, 0, 0, 0},
		{'P', 'K', 3, 4, 0, 0, 0, 0},
		{0x1f, 0x8b, 0x08, 0x00},
		append(make([]byte, 257), []byte("ustar")...),
		{0xff, 0xfe, 0x00, '\n'},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		target := t.TempDir()
		if err := os.WriteFile(filepath.Join(target, "hostile-bytes"), data, 0o600); err != nil {
			t.Fatal(err)
		}
		result, err := Scan(target, DefaultLimits())
		if err != nil {
			t.Fatalf("scan bounded regular bytes: %v", err)
		}
		if len(result.Files) != 1 || result.Files[0].Path != "hostile-bytes" || result.Files[0].Kind != "regular" {
			t.Fatalf("inventory structure changed: %#v", result.Files)
		}
		if len(result.RootDigest) != 64 {
			t.Fatalf("root digest length = %d", len(result.RootDigest))
		}
		if _, err := hex.DecodeString(result.RootDigest); err != nil {
			t.Fatalf("root digest is not hexadecimal: %v", err)
		}
	})
}
