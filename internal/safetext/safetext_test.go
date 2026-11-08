package safetext

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestDiagnosticNeutralizesControlsAndMalformedUTF8(t *testing.T) {
	input := append([]byte("before\x1b[31m\u009b\u061c\u200e\u200f\u202eafter\u2066\n\tkept"), 0xff, 0xfe)
	got := Diagnostic(input, 1024)
	if got != "before?[31m?????after?\n\tkept??" {
		t.Fatalf("Diagnostic() = %q", got)
	}
	if len(got) > len(input) {
		t.Fatalf("diagnostic grew from %d to %d bytes", len(input), len(got))
	}
}

func FuzzDiagnosticIsBoundedPlainText(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("plain text\n"),
		[]byte("before\x1b[31m\u202eafter"),
		{0xff, 0xfe, 0x00, '\n', '\t'},
	} {
		f.Add(seed, uint16(1024))
	}
	f.Fuzz(func(t *testing.T, data []byte, rawLimit uint16) {
		limit := int(rawLimit)
		got := Diagnostic(data, limit)
		if len(got) > limit {
			t.Fatalf("Diagnostic(%d bytes, %d) returned %d bytes", len(data), limit, len(got))
		}
		if !utf8.ValidString(got) {
			t.Fatalf("Diagnostic returned malformed UTF-8: %q", got)
		}
		for _, value := range got {
			if forbiddenRune(value) {
				t.Fatalf("Diagnostic retained forbidden control U+%04X", value)
			}
		}
	})
}

func TestDiagnosticReplacesEveryUnicodeBidiControl(t *testing.T) {
	controls := []rune{0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069}
	if got := Diagnostic([]byte(string(controls)), 1024); got != strings.Repeat("?", len(controls)) {
		t.Fatalf("bidi controls were not fully replaced: %q", got)
	}
}

func TestDiagnosticBoundsBeforeProcessBoundary(t *testing.T) {
	for _, limit := range []int{0, 1, 8, 13, 14, 64} {
		got := Diagnostic([]byte(strings.Repeat("x", 256)), limit)
		if len(got) > limit {
			t.Errorf("limit %d produced %d bytes", limit, len(got))
		}
	}
	got := Diagnostic([]byte(strings.Repeat("x", 256)), 64)
	if len(got) != 64 || !strings.HasSuffix(got, truncationMarker) {
		t.Fatalf("bounded diagnostic = %d bytes, %q", len(got), got)
	}
}
