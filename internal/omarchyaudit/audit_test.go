package omarchyaudit

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func TestDecodeEvidenceInputHashesTheExactParsedBytes(t *testing.T) {
	first, err := json.Marshal(validAudit())
	if err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), first...)
	changed = append(changed[:len(changed)-1], []byte(" \n}")...)

	for _, data := range [][]byte{first, changed} {
		audit, input, err := DecodeEvidenceInput(data, FormatPR8439Revision732b104)
		if err != nil {
			t.Fatal(err)
		}
		want := fmt.Sprintf("%x", sha256.Sum256(data))
		if audit.ID != "example.plugin" || input.DocumentSHA256 != want {
			t.Fatalf("decoded input = %#v, digest %q want %q", audit, input.DocumentSHA256, want)
		}
		if input.SubjectRootDigest != "" || input.Format != report.OmarchyAuditInputFormat || input.Version != report.OmarchyAuditInputVersion {
			t.Fatalf("current format claimed snapshot binding: %#v", input)
		}
	}
	_, firstInput, _ := DecodeEvidenceInput(first, FormatPR8439Revision732b104)
	_, changedInput, _ := DecodeEvidenceInput(changed, FormatPR8439Revision732b104)
	if firstInput.DocumentSHA256 == changedInput.DocumentSHA256 {
		t.Fatal("different parsed bytes produced the same document digest")
	}
}

func validAudit() Report {
	ok := true
	return Report{
		ID: "example.plugin", PluginDir: "/host/path/not-opened", Valid: true, ValidateStatus: "valid", Provenance: Provenance{Git: true, RemoteOK: &ok},
		Declared: Declared{Commands: []string{}, Network: []string{}, Reads: []string{}, Writes: []string{}},
		Observed: Observed{Commands: []Command{{Name: "curl"}}, Network: []Host{{Host: "example.test"}}, Reads: []Path{}, Writes: []Path{}},
		Risks:    []Risk{}, Summary: Summary{UndeclaredCommands: 1, UndeclaredNetwork: 1}, Verdict: Verdict{Level: "moderate", Reasons: []string{"one observation"}},
	}
}

func TestReadFileRejectsSymlinkAndBoundsInput(t *testing.T) {
	directory := t.TempDir()
	regular := filepath.Join(directory, "audit.json")
	if err := os.WriteFile(regular, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadFile(regular); err != nil || string(data) != "{}" {
		t.Fatalf("read = %q, %v", data, err)
	}
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(link); err == nil {
		t.Fatal("symlink audit accepted")
	}
	large := filepath.Join(directory, "large.json")
	if err := os.WriteFile(large, make([]byte, MaxInputBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(large); err == nil {
		t.Fatal("oversized audit file accepted")
	}
}

func TestDecodePinnedAuditFormatStrictly(t *testing.T) {
	data, err := json.Marshal(validAudit())
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(data, FormatPR8439Revision732b104)
	if err != nil || decoded.ID != "example.plugin" || decoded.Observed.Commands[0].Name != "curl" {
		t.Fatalf("decoded = %#v, %v", decoded, err)
	}
	for _, test := range []struct {
		name   string
		data   []byte
		format string
	}{
		{"unknown format", data, "latest"},
		{"unknown field", append(data[:len(data)-1], []byte(`,"future":true}`)...), FormatPR8439Revision732b104},
		{"duplicate member", []byte(`{"id":"first","id":"second"}`), FormatPR8439Revision732b104},
		{"trailing value", append(data, []byte(` {}`)...), FormatPR8439Revision732b104},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Decode(test.data, test.format); err == nil {
				t.Fatal("invalid audit accepted")
			}
		})
	}
}

func TestDecodeRejectsIncorrectlyCasedMembersAtEveryLevel(t *testing.T) {
	audit := validAudit()
	audit.Risks = []Risk{{Severity: "medium", Kind: "example", Detail: "detail"}}
	audit.Summary.Risks = 1
	canonical, err := json.Marshal(audit)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{"id alias alongside canonical", addRootMember(canonical, `"ID":"replacement"`)},
		{"observed alias alongside canonical", addRootMember(canonical, `"OBSERVED":{"commands":[],"network":[],"reads":[],"writes":[]}`)},
		{"single incorrectly cased id", bytes.Replace(canonical, []byte(`"id"`), []byte(`"ID"`), 1)},
		{"nested command name alias", bytes.Replace(canonical, []byte(`"name":"curl"`), []byte(`"name":"curl","NAME":"hidden"`), 1)},
		{"nested risk severity alias", bytes.Replace(canonical, []byte(`"severity":"medium"`), []byte(`"severity":"medium","SEVERITY":"high"`), 1)},
		{"escaped exact duplicate", addRootMember(canonical, `"\u0069d":"replacement"`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Decode(test.data, FormatPR8439Revision732b104); err == nil {
				t.Fatal("incorrectly cased or duplicate schema member was accepted")
			}
		})
	}
}

func TestDecodeRejectsMalformedUnicodeBeforeJSONNormalization(t *testing.T) {
	canonical, err := json.Marshal(validAudit())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		replacement []byte
	}{
		{"raw invalid UTF-8", []byte{'"', 0xff, '"'}},
		{"lone high surrogate", []byte(`"\ud800"`)},
		{"lone low surrogate", []byte(`"\udc00"`)},
		{"malformed surrogate pair", []byte(`"\ud800\u0041"`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := bytes.Replace(canonical, []byte(`"example.plugin"`), test.replacement, 1)
			if _, err := Decode(data, FormatPR8439Revision732b104); err == nil {
				t.Fatal("malformed Unicode was accepted")
			}
		})
	}
	invalidMember := bytes.Replace(canonical, []byte(`"id"`), []byte{'"', 'i', 0xff, '"'}, 1)
	if _, err := Decode(invalidMember, FormatPR8439Revision732b104); err == nil {
		t.Fatal("raw invalid UTF-8 in member name was accepted")
	}
	validPair := bytes.Replace(canonical, []byte(`"example.plugin"`), []byte(`"\ud83d\ude00"`), 1)
	if decoded, err := Decode(validPair, FormatPR8439Revision732b104); err != nil || decoded.ID != "😀" {
		t.Fatalf("valid surrogate pair decoded as ID %q, error %v", decoded.ID, err)
	}

	audit := validAudit()
	audit.Risks = []Risk{{Severity: "medium", Kind: "unicode", Detail: "genuine � value"}}
	audit.Summary.Risks = 1
	data, err := json.Marshal(audit)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(data, FormatPR8439Revision732b104)
	if err != nil {
		t.Fatalf("genuine U+FFFD rejected: %v", err)
	}
	if got := decoded.Risks[0].Detail; got != audit.Risks[0].Detail {
		t.Fatalf("U+FFFD changed during decode: got %q want %q", got, audit.Risks[0].Detail)
	}
}

func TestDecodeRejectsExcessiveJSONNesting(t *testing.T) {
	canonical, err := json.Marshal(validAudit())
	if err != nil {
		t.Fatal(err)
	}
	deep := []byte(strings.Repeat("[", MaxJSONDepth+2) + `"example.plugin"` + strings.Repeat("]", MaxJSONDepth+2))
	data := bytes.Replace(canonical, []byte(`"example.plugin"`), deep, 1)
	if _, err := Decode(data, FormatPR8439Revision732b104); err == nil || !strings.Contains(err.Error(), "nesting exceeds") {
		t.Fatalf("over-depth audit error = %v", err)
	}
}

func TestDecodeEvidenceInputRejectsAliasesThatHideObservationsAndRisks(t *testing.T) {
	audit := validAudit()
	audit.Risks = []Risk{{Severity: "high", Kind: "hidden", Detail: "must remain visible"}}
	audit.Summary.HighRisks = 1
	audit.Summary.Risks = 1
	canonical, err := json.Marshal(audit)
	if err != nil {
		t.Fatal(err)
	}
	hostile := addRootMember(canonical, `"OBSERVED":{"commands":[],"network":[],"reads":[],"writes":[]},"RISKS":[],"SUMMARY":{"undeclaredCommands":0,"undeclaredNetwork":0,"undeclaredReads":0,"undeclaredWrites":0,"highRisks":0,"risks":0}`)
	if _, _, err := DecodeEvidenceInput(hostile, FormatPR8439Revision732b104); err == nil {
		t.Fatal("case aliases hid imported observations and risks")
	}
}

func addRootMember(data []byte, member string) []byte {
	result := append([]byte(nil), data[:len(data)-1]...)
	result = append(result, ',')
	result = append(result, member...)
	return append(result, '}')
}

func TestAuditCollectionsAndStringsAreBounded(t *testing.T) {
	r := validAudit()
	r.Observed.Network = []Host{}
	r.Observed.Commands = make([]Command, MaxObservations)
	for index := range r.Observed.Commands {
		r.Observed.Commands[index] = Command{Name: fmt.Sprintf("command-%d", index)}
	}
	r.Summary.UndeclaredCommands, r.Summary.UndeclaredNetwork = MaxObservations, 0
	if err := r.Validate(); err != nil {
		t.Fatalf("exact observation limit rejected: %v", err)
	}
	r.Observed.Commands = append(r.Observed.Commands, Command{Name: "first-over"})
	r.Summary.UndeclaredCommands++
	if err := r.Validate(); err == nil {
		t.Fatal("oversized observation collection accepted")
	}
	r = validAudit()
	r.PluginDir = strings.Repeat("x", MaxStringBytes+1)
	if err := r.Validate(); err == nil {
		t.Fatal("oversized hostile string accepted")
	}
	if _, err := Decode(make([]byte, MaxInputBytes+1), FormatPR8439Revision732b104); err == nil {
		t.Fatal("oversized input accepted")
	}
}

func FuzzDecodeNeverPanics(f *testing.F) {
	data, _ := json.Marshal(validAudit())
	f.Add(data)
	f.Add([]byte(`{"observed":{"commands":[]}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxInputBytes {
			t.Skip()
		}
		_, _ = Decode(data, FormatPR8439Revision732b104)
	})
}
