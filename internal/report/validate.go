package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// Decode validates the scanner's trust-boundary output before another
// component presents it. It deliberately accepts exactly one JSON value and
// rejects fields unknown to this version of the report contract.
func Decode(data []byte) (Report, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value Report
	if err := decoder.Decode(&value); err != nil {
		return Report{}, fmt.Errorf("decode report: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Report{}, errors.New("decode report: multiple JSON values")
		}
		return Report{}, fmt.Errorf("decode report trailer: %w", err)
	}
	if err := value.Validate(); err != nil {
		return Report{}, err
	}
	return value, nil
}

func (r Report) Validate() error {
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported report schema %q", r.SchemaVersion)
	}
	if !oneOf(string(r.Status), string(StatusComplete), string(StatusIncomplete), string(StatusError)) {
		return fmt.Errorf("invalid report status %q", r.Status)
	}
	if r.Scan.ScannerVersion == "" || r.Scan.PolicyVersion == "" {
		return errors.New("scanner and policy versions are required")
	}
	if r.Scan.StartedAt.IsZero() || r.Scan.CompletedAt.IsZero() || r.Scan.CompletedAt.Before(r.Scan.StartedAt) {
		return errors.New("invalid scan timestamps")
	}
	if r.Target.DisplayName == "" || r.Target.FileCount < 0 || r.Target.ReadBytes < 0 || r.Target.BinaryBytes < 0 {
		return errors.New("invalid target metadata")
	}

	operations := make(map[string]struct{}, len(r.Operations))
	for index, operation := range r.Operations {
		if operation.ID == "" {
			return fmt.Errorf("operation %d has no ID", index)
		}
		if _, exists := operations[operation.ID]; exists {
			return fmt.Errorf("duplicate operation ID %q", operation.ID)
		}
		operations[operation.ID] = struct{}{}
		if err := validateScopeConfidence(operation.Scope, operation.Confidence); err != nil {
			return fmt.Errorf("operation %q: %w", operation.ID, err)
		}
		if err := validateEvidence(operation.Evidence); err != nil {
			return fmt.Errorf("operation %q: %w", operation.ID, err)
		}
	}
	for _, resource := range r.Resources {
		if resource.ID == "" || resource.Kind == "" || resource.Access == "" || resource.Value == "" {
			return errors.New("resource identity, kind, access, and value are required")
		}
		if err := validateScopeConfidence(resource.Scope, resource.Confidence); err != nil {
			return fmt.Errorf("resource %q: %w", resource.ID, err)
		}
		if err := validateEvidence(resource.Evidence); err != nil {
			return fmt.Errorf("resource %q: %w", resource.ID, err)
		}
		if resource.RelatedOperationID != "" {
			if _, exists := operations[resource.RelatedOperationID]; !exists {
				return fmt.Errorf("resource %q references missing operation %q", resource.ID, resource.RelatedOperationID)
			}
		}
	}
	for _, finding := range r.Findings {
		if finding.ID == "" || finding.Category == "" || finding.Title == "" || finding.Explanation == "" || finding.Provenance == "" {
			return errors.New("finding identity, category, title, explanation, and provenance are required")
		}
		if !oneOf(string(finding.Claim), string(ClaimFact), string(ClaimInference), string(ClaimUnknown)) {
			return fmt.Errorf("finding %q has invalid claim %q", finding.ID, finding.Claim)
		}
		if !oneOf(string(finding.Severity), string(SeverityCritical), string(SeverityHigh), string(SeverityMedium), string(SeverityLow), string(SeverityInformational)) {
			return fmt.Errorf("finding %q has invalid severity %q", finding.ID, finding.Severity)
		}
		if err := validateScopeConfidence(finding.Scope, finding.Confidence); err != nil {
			return fmt.Errorf("finding %q: %w", finding.ID, err)
		}
		for _, evidence := range finding.Evidence {
			if err := validateEvidence(evidence); err != nil {
				return fmt.Errorf("finding %q: %w", finding.ID, err)
			}
		}
		for _, related := range finding.Related {
			if _, exists := operations[related]; !exists {
				return fmt.Errorf("finding %q references missing operation %q", finding.ID, related)
			}
		}
	}
	if r.Status == StatusComplete && (len(r.Limitations) != 0 || len(r.Errors) != 0) {
		return errors.New("complete report cannot contain limitations or scan errors")
	}
	return nil
}

func validateScopeConfidence(scope Scope, confidence Confidence) error {
	if !oneOf(string(scope), string(ScopeRuntime), string(ScopeTooling), string(ScopeUnknown)) {
		return fmt.Errorf("invalid scope %q", scope)
	}
	if !oneOf(string(confidence), string(ConfidenceHigh), string(ConfidenceMedium), string(ConfidenceLow)) {
		return fmt.Errorf("invalid confidence %q", confidence)
	}
	return nil
}

func validateEvidence(evidence Evidence) error {
	if evidence.Path == "" {
		return errors.New("evidence path is required")
	}
	clean := path.Clean(strings.ReplaceAll(evidence.Path, "\\", "/"))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return fmt.Errorf("unsafe evidence path %q", evidence.Path)
	}
	if evidence.LineStart < 0 || evidence.LineEnd < 0 || (evidence.LineEnd != 0 && evidence.LineEnd < evidence.LineStart) {
		return fmt.Errorf("invalid evidence lines for %q", evidence.Path)
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
