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
	if err := rejectDuplicateMembers(data); err != nil {
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

func rejectDuplicateMembers(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func(json.Token) error
	walk = func(token json.Token) error {
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]bool)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("Omarchy audit object member name is not a string")
				}
				if seen[key] {
					return fmt.Errorf("Omarchy audit repeats JSON member %q", key)
				}
				seen[key] = true
				value, err := decoder.Token()
				if err != nil {
					return err
				}
				if err := walk(value); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		case '[':
			for decoder.More() {
				value, err := decoder.Token()
				if err != nil {
					return err
				}
				if err := walk(value); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		default:
			return errors.New("Omarchy audit contains an unexpected JSON delimiter")
		}
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode Omarchy audit tokens: %w", err)
	}
	if err := walk(token); err != nil {
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
