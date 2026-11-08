package boundedjson

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestEncodeExactLimitAndFirstByteOver(t *testing.T) {
	encoded, err := Encode("<>\u202e", 1024, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `\u003c\u003e`) {
		t.Fatalf("HTML-sensitive characters were not escaped: %q", encoded)
	}
	exact, err := Encode("<>\u202e", len(encoded), "")
	if err != nil || string(exact) != string(encoded) {
		t.Fatalf("exact limit = %q, %v", exact, err)
	}
	over, err := Encode("<>\u202e", len(encoded)-1, "")
	if !errors.Is(err, ErrLimitExceeded) || over != nil {
		t.Fatalf("first byte over = %q, %v", over, err)
	}
}

func TestEncodeRejectsInvalidLimitWithoutOutput(t *testing.T) {
	if output, err := Encode(map[string]string{}, 0, ""); !errors.Is(err, ErrLimitExceeded) || output != nil {
		t.Fatalf("zero limit = %q, %v", output, err)
	}
}

func TestEncodeHostileStringUsesStandardJSONNormalization(t *testing.T) {
	hostile := string([]byte{'<', 0, 0x85, 0xff}) + "\u202e"
	encoded, err := Encode(hostile, 1024, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{{'<'}, {0}, {0x85}, {0xff}} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatalf("encoded hostile string contains raw bytes %x: %q", forbidden, encoded)
		}
	}
	for _, required := range []string{`\u003c`, `\u0000`, "�"} {
		if !bytes.Contains(encoded, []byte(required)) {
			t.Fatalf("encoded hostile string lacks %q: %q", required, encoded)
		}
	}
}

func FuzzEncodeNeverPanics(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		[]byte("ordinary"),
		[]byte("<>\\\"\x00\x1b"),
		{0xff, 0xfe, 0x80},
		[]byte("\u202e\u2066"),
	} {
		f.Add(seed, uint16(256))
	}
	f.Fuzz(func(t *testing.T, input []byte, rawLimit uint16) {
		limit := int(rawLimit)
		output, err := Encode(string(input), limit, "fuzz")
		if err != nil {
			if output != nil {
				t.Fatalf("failed encoding returned partial output: %q", output)
			}
			return
		}
		if len(output) > limit {
			t.Fatalf("encoded %d bytes with limit %d", len(output), limit)
		}
	})
}
