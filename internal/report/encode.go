package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
)

var ErrEncodedReportTooLarge = errors.New("canonical encoded report exceeds 16 MiB limit")

type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (value *boundedBuffer) Write(data []byte) (int, error) {
	if len(data) > value.limit-value.Len() {
		return 0, ErrEncodedReportTooLarge
	}
	return value.Buffer.Write(data)
}

// EncodeCanonical validates and encodes the exact HTML-escaped representation
// accepted at the report boundary. The bounded buffer never retains more than
// MaxEncodedReportBytes.
func EncodeCanonical(value Report) ([]byte, error) {
	canonical, err := canonicalReport(value)
	if err != nil {
		return nil, err
	}
	buffer := &boundedBuffer{limit: MaxEncodedReportBytes}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(canonical); err != nil {
		return nil, err
	}
	return append([]byte(nil), buffer.Bytes()...), nil
}

// WriteCanonical performs no destination write until complete bounded encoding
// succeeds, so consumers never receive a partial successful-looking report.
func WriteCanonical(destination io.Writer, value Report) error {
	encoded, err := EncodeCanonical(value)
	if err != nil {
		return err
	}
	_, err = destination.Write(encoded)
	return err
}

func canonicalReport(value Report) (Report, error) {
	if value.Target.Manifest != nil {
		manifest := *value.Target.Manifest
		manifest.Kinds = append([]string(nil), manifest.Kinds...)
		sort.Strings(manifest.Kinds)
		manifest.EntryPoints = cloneStringMap(manifest.EntryPoints)
		value.Target.Manifest = &manifest
	}
	value.EvidenceInputs = append(make([]EvidenceInput, 0, len(value.EvidenceInputs)), value.EvidenceInputs...)
	value.Inventory = append(make([]File, 0, len(value.Inventory)), value.Inventory...)
	value.Operations = append(make([]Operation, 0, len(value.Operations)), value.Operations...)
	value.Resources = append(make([]Resource, 0, len(value.Resources)), value.Resources...)
	value.Findings = append(make([]Finding, 0, len(value.Findings)), value.Findings...)
	value.Unknowns = append(make([]Unknown, 0, len(value.Unknowns)), value.Unknowns...)
	value.Relationships = append(make([]Relationship, 0, len(value.Relationships)), value.Relationships...)
	value.Limitations = append(make([]Limitation, 0, len(value.Limitations)), value.Limitations...)
	value.Errors = append(make([]ScanError, 0, len(value.Errors)), value.Errors...)
	sort.Slice(value.EvidenceInputs, func(i, j int) bool { return value.EvidenceInputs[i].ID < value.EvidenceInputs[j].ID })
	sort.Slice(value.Inventory, func(i, j int) bool { return value.Inventory[i].Path < value.Inventory[j].Path })
	sort.Slice(value.Operations, func(i, j int) bool { return value.Operations[i].ID < value.Operations[j].ID })
	sort.Slice(value.Resources, func(i, j int) bool { return value.Resources[i].ID < value.Resources[j].ID })
	sort.Slice(value.Findings, func(i, j int) bool { return value.Findings[i].ID < value.Findings[j].ID })
	sort.Slice(value.Unknowns, func(i, j int) bool { return value.Unknowns[i].ID < value.Unknowns[j].ID })
	sort.Slice(value.Relationships, func(i, j int) bool {
		return relationshipTuple(value.Relationships[i]) < relationshipTuple(value.Relationships[j])
	})
	sort.Slice(value.Limitations, func(i, j int) bool {
		return compareLimitation(value.Limitations[i], value.Limitations[j]) < 0
	})
	sort.Slice(value.Errors, func(i, j int) bool { return compareScanError(value.Errors[i], value.Errors[j]) < 0 })
	for index := range value.Inventory {
		if value.Inventory[index].Binary != nil {
			binary := *value.Inventory[index].Binary
			binary.Libraries = sortedStrings(binary.Libraries)
			binary.ImportedSymbols = sortedStrings(binary.ImportedSymbols)
			binary.ExtractedStrings = sortedStrings(binary.ExtractedStrings)
			binary.EmbeddedURLs = sortedStrings(binary.EmbeddedURLs)
			binary.FileCapabilities = sortedStrings(binary.FileCapabilities)
			value.Inventory[index].Binary = &binary
		}
		if value.Inventory[index].Archive != nil {
			archive := *value.Inventory[index].Archive
			// Archive entry order is retained because it records package order and
			// may contain repeated path names with distinct positions.
			archive.Entries = append([]ArchiveEntry(nil), archive.Entries...)
			value.Inventory[index].Archive = &archive
		}
	}
	for index := range value.Operations {
		// Argument position is executable-call semantics and is deliberately
		// preserved rather than sorted.
		value.Operations[index].Arguments = append([]string(nil), value.Operations[index].Arguments...)
	}
	for index := range value.Findings {
		value.Findings[index].Evidence = append(make([]Evidence, 0, len(value.Findings[index].Evidence)), value.Findings[index].Evidence...)
		value.Findings[index].Related = append(make([]string, 0, len(value.Findings[index].Related)), value.Findings[index].Related...)
		sortEvidence(value.Findings[index].Evidence)
		sort.Strings(value.Findings[index].Related)
	}
	for index := range value.Unknowns {
		value.Unknowns[index].Evidence = append(make([]Evidence, 0, len(value.Unknowns[index].Evidence)), value.Unknowns[index].Evidence...)
		value.Unknowns[index].Origins = append(make([]ValueOrigin, 0, len(value.Unknowns[index].Origins)), value.Unknowns[index].Origins...)
		value.Unknowns[index].AffectedOperations = append(make([]string, 0, len(value.Unknowns[index].AffectedOperations)), value.Unknowns[index].AffectedOperations...)
		value.Unknowns[index].SuppressedRules = append(make([]string, 0, len(value.Unknowns[index].SuppressedRules)), value.Unknowns[index].SuppressedRules...)
		sortEvidence(value.Unknowns[index].Evidence)
		// Origin order is a bounded data-flow trace and therefore semantic.
		sort.Strings(value.Unknowns[index].AffectedOperations)
		sort.Strings(value.Unknowns[index].SuppressedRules)
	}
	for index := range value.Relationships {
		if value.Relationships[index].Comparison != nil {
			basis := *value.Relationships[index].Comparison
			value.Relationships[index].Comparison = &basis
		}
	}
	coverage := coverageFromInventory(value.Inventory)
	if err := value.BuildReviewSummary(coverage); err != nil {
		return Report{}, err
	}
	if err := value.Validate(); err != nil {
		return Report{}, err
	}
	return value, nil
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func sortEvidence(values []Evidence) {
	sort.Slice(values, func(i, j int) bool { return compareEvidence(values[i], values[j]) < 0 })
}

func compareString(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func compareInt(left, right int) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func compareEvidence(left, right Evidence) int {
	if result := compareString(left.InputID, right.InputID); result != 0 {
		return result
	}
	if result := compareString(left.Path, right.Path); result != 0 {
		return result
	}
	if result := compareInt(left.LineStart, right.LineStart); result != 0 {
		return result
	}
	if result := compareInt(left.LineEnd, right.LineEnd); result != 0 {
		return result
	}
	if result := compareString(left.Operation, right.Operation); result != 0 {
		return result
	}
	return compareString(left.Excerpt, right.Excerpt)
}
func relationshipTuple(v Relationship) string {
	return string(v.Type) + "\x00" + string(v.FromKind) + "\x00" + v.From + "\x00" + string(v.ToKind) + "\x00" + v.To
}

func compareLimitation(left, right Limitation) int {
	if result := compareString(left.Code, right.Code); result != 0 {
		return result
	}
	if result := compareString(left.Path, right.Path); result != 0 {
		return result
	}
	if result := compareString(string(left.Scope), string(right.Scope)); result != 0 {
		return result
	}
	return compareString(left.Description, right.Description)
}

func compareScanError(left, right ScanError) int {
	if result := compareString(left.Code, right.Code); result != 0 {
		return result
	}
	if result := compareString(left.Path, right.Path); result != 0 {
		return result
	}
	return compareString(left.Message, right.Message)
}
