package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
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
		return limitationTuple(value.Limitations[i]) < limitationTuple(value.Limitations[j])
	})
	sort.Slice(value.Errors, func(i, j int) bool { return errorTuple(value.Errors[i]) < errorTuple(value.Errors[j]) })
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
		sort.Slice(value.Unknowns[index].Origins, func(i, j int) bool {
			return string(value.Unknowns[index].Origins[i].Kind)+"\x00"+value.Unknowns[index].Origins[i].Name+"\x00"+evidenceTuple(value.Unknowns[index].Origins[i].Evidence) < string(value.Unknowns[index].Origins[j].Kind)+"\x00"+value.Unknowns[index].Origins[j].Name+"\x00"+evidenceTuple(value.Unknowns[index].Origins[j].Evidence)
		})
		sort.Strings(value.Unknowns[index].AffectedOperations)
		sort.Strings(value.Unknowns[index].SuppressedRules)
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

func sortEvidence(values []Evidence) {
	sort.Slice(values, func(i, j int) bool { return evidenceTuple(values[i]) < evidenceTuple(values[j]) })
}
func evidenceTuple(v Evidence) string {
	return v.InputID + "\x00" + v.Path + "\x00" + strconv.Itoa(v.LineStart) + "\x00" + strconv.Itoa(v.LineEnd) + "\x00" + v.Operation + "\x00" + v.Excerpt
}
func relationshipTuple(v Relationship) string {
	return string(v.Type) + "\x00" + string(v.FromKind) + "\x00" + v.From + "\x00" + string(v.ToKind) + "\x00" + v.To
}
func limitationTuple(v Limitation) string {
	return v.Code + "\x00" + v.Path + "\x00" + string(v.Scope) + "\x00" + v.Description
}
func errorTuple(v ScanError) string { return v.Code + "\x00" + v.Path + "\x00" + v.Message }
