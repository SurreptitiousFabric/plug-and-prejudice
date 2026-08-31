// Package omarchyaudit decodes a pinned, bounded snapshot of Omarchy's
// proposed plugin-audit JSON. It never runs Omarchy or opens plugin paths.
package omarchyaudit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

func ReadFile(name string) ([]byte, error) {
	clean, err := filepath.Abs(name)
	if err != nil {
		return nil, fmt.Errorf("resolve Omarchy audit path: %w", err)
	}
	linked, err := os.Lstat(clean)
	if err != nil {
		return nil, fmt.Errorf("inspect Omarchy audit path: %w", err)
	}
	if !linked.Mode().IsRegular() || linked.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("Omarchy audit path must be a non-symlink regular file")
	}
	file, err := os.Open(clean)
	if err != nil {
		return nil, fmt.Errorf("open Omarchy audit: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(linked, opened) {
		return nil, errors.New("Omarchy audit path identity changed while being opened")
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxInputBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Omarchy audit: %w", err)
	}
	if len(data) > MaxInputBytes {
		return nil, fmt.Errorf("Omarchy audit exceeds %d-byte input limit", MaxInputBytes)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) || int64(len(data)) != after.Size() {
		return nil, errors.New("Omarchy audit changed while it was read")
	}
	return data, nil
}

const (
	FormatPR8439Revision732b104 = report.OmarchyAuditInputVersion
	MaxInputBytes               = 1 << 20
	MaxObservations             = 4096
	MaxTotalObservations        = 4096
	MaxRisks                    = 1024
	MaxReasons                  = 1024
	MaxStringBytes              = 4 << 10
	MaxJSONDepth                = 64
)

type Report struct {
	ID                   string     `json:"id"`
	PluginDir            string     `json:"pluginDir"`
	FirstParty           bool       `json:"firstParty"`
	Valid                bool       `json:"valid"`
	ValidateStatus       string     `json:"validateStatus"`
	CapabilitiesDeclared bool       `json:"capabilitiesDeclared"`
	Provenance           Provenance `json:"provenance"`
	Declared             Declared   `json:"declared"`
	Observed             Observed   `json:"observed"`
	Risks                []Risk     `json:"risks"`
	Summary              Summary    `json:"summary"`
	Verdict              Verdict    `json:"verdict"`
}

type Provenance struct {
	Git        bool   `json:"git"`
	Remote     string `json:"remote,omitempty"`
	Commit     string `json:"commit,omitempty"`
	RemoteOK   *bool  `json:"remoteOk,omitempty"`
	RemoteNote string `json:"remoteNote,omitempty"`
}

type Declared struct {
	Commands []string `json:"commands"`
	Network  []string `json:"network"`
	Reads    []string `json:"reads"`
	Writes   []string `json:"writes"`
}
type Observed struct {
	Commands []Command `json:"commands"`
	Network  []Host    `json:"network"`
	Reads    []Path    `json:"reads"`
	Writes   []Path    `json:"writes"`
}
type Command struct {
	Name     string `json:"name"`
	Declared bool   `json:"declared"`
}
type Host struct {
	Host     string `json:"host"`
	Declared bool   `json:"declared"`
}
type Path struct {
	Path     string `json:"path"`
	Declared bool   `json:"declared"`
}
type Risk struct {
	Severity string `json:"severity"`
	Kind     string `json:"kind"`
	Detail   string `json:"detail"`
}
type Summary struct {
	UndeclaredCommands int `json:"undeclaredCommands"`
	UndeclaredNetwork  int `json:"undeclaredNetwork"`
	UndeclaredReads    int `json:"undeclaredReads"`
	UndeclaredWrites   int `json:"undeclaredWrites"`
	HighRisks          int `json:"highRisks"`
	Risks              int `json:"risks"`
}
type Verdict struct {
	Level   string   `json:"level"`
	Reasons []string `json:"reasons"`
}

func Decode(data []byte, format string) (Report, error) {
	if format != FormatPR8439Revision732b104 {
		return Report{}, fmt.Errorf("unsupported Omarchy audit format %q", format)
	}
	if len(data) > MaxInputBytes {
		return Report{}, fmt.Errorf("Omarchy audit exceeds %d-byte input limit", MaxInputBytes)
	}
	if err := validateJSONStructure(data, reflect.TypeOf(Report{})); err != nil {
		return Report{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var result Report
	if err := decoder.Decode(&result); err != nil {
		return Report{}, fmt.Errorf("decode Omarchy audit: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Report{}, errors.New("Omarchy audit contains more than one JSON value")
		}
		return Report{}, fmt.Errorf("decode trailing Omarchy audit data: %w", err)
	}
	if err := result.Validate(); err != nil {
		return Report{}, err
	}
	return result, nil
}

// DecodeEvidenceInput copies one bounded caller-supplied byte sequence, hashes
// that retained copy, and parses the same copy. The resulting document digest
// identifies only the imported document bytes, never the target snapshot.
func DecodeEvidenceInput(data []byte, format string) (Report, report.EvidenceInput, error) {
	if len(data) > MaxInputBytes {
		return Report{}, report.EvidenceInput{}, fmt.Errorf("Omarchy audit exceeds %d-byte input limit", MaxInputBytes)
	}
	retained := append([]byte(nil), data...)
	audit, err := Decode(retained, format)
	if err != nil {
		return Report{}, report.EvidenceInput{}, err
	}
	input := report.NewOmarchyAuditEvidenceInput("input-omarchy-audit", "pinned Omarchy audit for "+audit.ID, retained)
	return audit, input, nil
}

// validateJSONStructure rejects malformed Unicode and enforces the pinned
// schema's exact member names before encoding/json can perform its
// case-insensitive struct-field matching.
func validateJSONStructure(data []byte, target reflect.Type) error {
	if !utf8.Valid(data) {
		return errors.New("Omarchy audit is not valid UTF-8")
	}
	if err := validateSurrogateEscapes(data); err != nil {
		return fmt.Errorf("decode Omarchy audit strings: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := consumeTypedJSONValue(decoder, target, 0); err != nil {
		return fmt.Errorf("decode Omarchy audit tokens: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("Omarchy audit contains more than one JSON value")
		}
		return fmt.Errorf("decode Omarchy audit tokens: %w", err)
	}
	return nil
}

func consumeTypedJSONValue(decoder *json.Decoder, target reflect.Type, depth int) error {
	if depth > MaxJSONDepth {
		return fmt.Errorf("JSON nesting exceeds limit %d", MaxJSONDepth)
	}
	for target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		fields := exactJSONFields(target)
		seen := make(map[string]struct{}, len(fields))
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return errors.New("object member name is not a string")
			}
			if _, exists := seen[name]; exists {
				return fmt.Errorf("duplicate JSON object member %q", name)
			}
			seen[name] = struct{}{}
			valueType, exists := fields[name]
			if !exists {
				return fmt.Errorf("unknown or incorrectly cased JSON member %q for %s", name, target)
			}
			if err := consumeTypedJSONValue(decoder, valueType, depth+1); err != nil {
				return err
			}
		}
	case '[':
		if target.Kind() != reflect.Slice && target.Kind() != reflect.Array {
			// Continue walking malformed composite values so their nesting is
			// still bounded; the typed decoder will reject the type mismatch.
			target = reflect.TypeOf([]any{})
		}
		for decoder.More() {
			if err := consumeTypedJSONValue(decoder, target.Elem(), depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	want := json.Delim('}')
	if delimiter == '[' {
		want = ']'
	}
	if closing != want {
		return fmt.Errorf("mismatched JSON delimiter %q", closing)
	}
	return nil
}

func exactJSONFields(target reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type)
	if target.Kind() != reflect.Struct {
		return fields
	}
	for index := 0; index < target.NumField(); index++ {
		field := target.Field(index)
		if field.PkgPath != "" {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" {
			name = field.Name
		}
		if name != "-" {
			fields[name] = field.Type
		}
	}
	return fields
}

func validateSurrogateEscapes(data []byte) error {
	inString, escaped := false, false
	for index := 0; index < len(data); index++ {
		value := data[index]
		if !inString {
			if value == '"' {
				inString = true
			}
			continue
		}
		if escaped {
			escaped = false
			if value != 'u' {
				continue
			}
			code, next, err := parseUnicodeEscape(data, index-1)
			if err != nil {
				return err
			}
			index = next - 1
			if code >= 0xd800 && code <= 0xdbff {
				if next+6 > len(data) || data[next] != '\\' || data[next+1] != 'u' {
					return errors.New("unpaired high UTF-16 surrogate escape")
				}
				low, after, err := parseUnicodeEscape(data, next)
				if err != nil || low < 0xdc00 || low > 0xdfff {
					return errors.New("malformed UTF-16 surrogate pair")
				}
				index = after - 1
			} else if code >= 0xdc00 && code <= 0xdfff {
				return errors.New("unpaired low UTF-16 surrogate escape")
			}
			continue
		}
		if value == '\\' {
			escaped = true
		} else if value == '"' {
			inString = false
		}
	}
	return nil
}

func parseUnicodeEscape(data []byte, slash int) (uint64, int, error) {
	if slash+6 > len(data) || data[slash] != '\\' || data[slash+1] != 'u' {
		return 0, slash, errors.New("malformed Unicode escape")
	}
	value, err := strconv.ParseUint(string(data[slash+2:slash+6]), 16, 16)
	if err != nil {
		return 0, slash, errors.New("malformed Unicode escape")
	}
	return value, slash + 6, nil
}

func (r Report) Validate() error {
	if r.ID == "" || r.Observed.Commands == nil || r.Observed.Network == nil || r.Observed.Reads == nil || r.Observed.Writes == nil || r.Risks == nil || r.Verdict.Reasons == nil ||
		r.Declared.Commands == nil || r.Declared.Network == nil || r.Declared.Reads == nil || r.Declared.Writes == nil {
		return errors.New("Omarchy audit has incomplete required structure")
	}
	if len(r.Observed.Commands) > MaxObservations || len(r.Observed.Network) > MaxObservations || len(r.Observed.Reads) > MaxObservations || len(r.Observed.Writes) > MaxObservations || len(r.Risks) > MaxRisks {
		return errors.New("Omarchy audit collection exceeds retained limit")
	}
	if len(r.Observed.Commands)+len(r.Observed.Network)+len(r.Observed.Reads)+len(r.Observed.Writes) > MaxTotalObservations {
		return errors.New("Omarchy audit aggregate observations exceed retained limit")
	}
	if len(r.Declared.Commands) > MaxObservations || len(r.Declared.Network) > MaxObservations || len(r.Declared.Reads) > MaxObservations || len(r.Declared.Writes) > MaxObservations || len(r.Verdict.Reasons) > MaxReasons {
		return errors.New("Omarchy audit declared or verdict collection exceeds retained limit")
	}
	values := []string{r.ID, r.PluginDir, r.ValidateStatus, r.Provenance.Remote, r.Provenance.Commit, r.Provenance.RemoteNote, r.Verdict.Level}
	for _, collection := range [][]string{r.Declared.Commands, r.Declared.Network, r.Declared.Reads, r.Declared.Writes, r.Verdict.Reasons} {
		values = append(values, collection...)
	}
	seen := make(map[string]bool)
	for _, item := range r.Observed.Commands {
		if item.Name == "" {
			return errors.New("Omarchy command observation is empty")
		}
		if seen["command\x00"+item.Name] {
			return errors.New("Omarchy audit repeats a command observation")
		}
		seen["command\x00"+item.Name] = true
		values = append(values, item.Name)
	}
	for _, item := range r.Observed.Network {
		if item.Host == "" {
			return errors.New("Omarchy network observation is empty")
		}
		if seen["network\x00"+item.Host] {
			return errors.New("Omarchy audit repeats a network observation")
		}
		seen["network\x00"+item.Host] = true
		values = append(values, item.Host)
	}
	for _, item := range append(append([]Path{}, r.Observed.Reads...), r.Observed.Writes...) {
		if item.Path == "" {
			return errors.New("Omarchy path observation is empty")
		}
		values = append(values, item.Path)
	}
	for _, risk := range r.Risks {
		if risk.Severity == "" || risk.Kind == "" || risk.Detail == "" {
			return errors.New("Omarchy risk is incomplete")
		}
		if risk.Severity != "medium" && risk.Severity != "high" {
			return fmt.Errorf("Omarchy risk has unsupported severity %q", risk.Severity)
		}
		values = append(values, risk.Severity, risk.Kind, risk.Detail)
	}
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil || len(encoded) > MaxStringBytes || !utf8.ValidString(value) {
			return errors.New("Omarchy audit string is invalid or exceeds its byte limit")
		}
	}
	if r.Summary.UndeclaredCommands < 0 || r.Summary.UndeclaredNetwork < 0 || r.Summary.UndeclaredReads < 0 || r.Summary.UndeclaredWrites < 0 || r.Summary.HighRisks < 0 || r.Summary.Risks < 0 {
		return errors.New("Omarchy audit summary count is negative")
	}
	if !oneOf(r.Verdict.Level, "minimal", "low", "moderate", "high", "critical") {
		return fmt.Errorf("Omarchy audit has unsupported verdict %q", r.Verdict.Level)
	}
	undeclaredCommands, undeclaredNetwork, undeclaredReads, undeclaredWrites, highRisks := 0, 0, 0, 0, 0
	for _, item := range r.Observed.Commands {
		if !item.Declared {
			undeclaredCommands++
		}
	}
	for _, item := range r.Observed.Network {
		if !item.Declared {
			undeclaredNetwork++
		}
	}
	for _, item := range r.Observed.Reads {
		if !item.Declared {
			undeclaredReads++
		}
	}
	for _, item := range r.Observed.Writes {
		if !item.Declared {
			undeclaredWrites++
		}
	}
	for _, item := range r.Risks {
		if item.Severity == "high" {
			highRisks++
		}
	}
	if r.Summary.UndeclaredCommands != undeclaredCommands || r.Summary.UndeclaredNetwork != undeclaredNetwork || r.Summary.UndeclaredReads != undeclaredReads || r.Summary.UndeclaredWrites != undeclaredWrites || r.Summary.HighRisks != highRisks || r.Summary.Risks != len(r.Risks) {
		return errors.New("Omarchy audit summary does not match retained observations")
	}
	return nil
}

func oneOf(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if value == candidate {
			return true
		}
	}
	return false
}
