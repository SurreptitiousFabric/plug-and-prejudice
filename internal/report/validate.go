package report

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"reflect"
	"strings"
)

// Decode validates the scanner's trust-boundary output before another
// component presents it. It deliberately accepts exactly one JSON value and
// rejects fields unknown to this version of the report contract.
func Decode(data []byte) (Report, error) {
	if len(data) > MaxEncodedReportBytes {
		return Report{}, fmt.Errorf("decode report: encoded input exceeds limit %d", MaxEncodedReportBytes)
	}
	if err := validateJSONObjectMembers(data); err != nil {
		return Report{}, fmt.Errorf("decode report: %w", err)
	}
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
	if err := validateCollectionBounds(r); err != nil {
		return err
	}
	if r.Inventory == nil || r.Operations == nil || r.Resources == nil || r.Findings == nil || r.Unknowns == nil || r.Relationships == nil || r.Limitations == nil || r.Errors == nil {
		return errors.New("top-level report collections must be JSON arrays, not null")
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
	if r.Scan.Sandboxed != (r.Scan.ResourceLimits != nil) {
		return errors.New("sandbox and resource-limit metadata must be established together")
	}
	if limits := r.Scan.ResourceLimits; limits != nil {
		if limits.MemoryMaxBytes <= 0 || limits.MemorySwapBytes < 0 || limits.TasksMax <= 0 || limits.CPUQuotaPercent <= 0 || limits.CPUQuotaPercent > 100 || limits.WallTimeSeconds <= 0 {
			return errors.New("invalid resource-limit metadata")
		}
	}
	if r.Target.DisplayName == "" || r.Target.FileCount < 0 || r.Target.ReadBytes < 0 || r.Target.BinaryBytes < 0 {
		return errors.New("invalid target metadata")
	}
	if r.Target.RootDigest != "" {
		decoded, err := hex.DecodeString(r.Target.RootDigest)
		if err != nil || len(decoded) != 32 || strings.ToLower(r.Target.RootDigest) != r.Target.RootDigest {
			return errors.New("target root digest must be 64 lowercase hexadecimal SHA-256 characters")
		}
	}
	if r.Target.FileCount != len(r.Inventory) {
		return fmt.Errorf("target file count %d does not match inventory length %d", r.Target.FileCount, len(r.Inventory))
	}
	if manifest := r.Target.Manifest; manifest != nil && (manifest.Kinds == nil || manifest.EntryPoints == nil) {
		return errors.New("manifest kinds and entry points must be JSON collections, not null")
	} else if manifest != nil && (len(manifest.Kinds) > MaxManifestKinds || len(manifest.EntryPoints) > MaxManifestEntryPoints) {
		return errors.New("manifest collections exceed structural limits")
	}
	files := make(map[string]struct{}, len(r.Inventory))
	var readBytes, binaryBytes int64
	for index, file := range r.Inventory {
		if file.Path == "" || file.Kind == "" || file.Mode == "" || file.Size < 0 {
			return fmt.Errorf("inventory file %d has invalid identity, kind, mode, or size", index)
		}
		if err := validateRelativePath(file.Path); err != nil {
			return fmt.Errorf("inventory file %d: %w", index, err)
		}
		if _, exists := files[file.Path]; exists {
			return fmt.Errorf("duplicate inventory path %q", file.Path)
		}
		files[file.Path] = struct{}{}
		if file.SHA256 != "" {
			decoded, err := hex.DecodeString(file.SHA256)
			if err != nil || len(decoded) != 32 || strings.ToLower(file.SHA256) != file.SHA256 {
				return fmt.Errorf("inventory file %q SHA-256 must be 64 lowercase hexadecimal characters", file.Path)
			}
		}
		if file.Inspected != (file.SHA256 != "") {
			return fmt.Errorf("inventory file %q inspection status and SHA-256 must be established together", file.Path)
		}
		if file.Inspected && (file.Kind != "regular" || file.ContentType == "") {
			return fmt.Errorf("inventory file %q is inspected without regular-file content metadata", file.Path)
		}
		if file.Inspected && file.SkipReason != "" {
			return fmt.Errorf("inventory file %q cannot be both inspected and skipped", file.Path)
		}
		switch file.Analysis {
		case AnalysisNotApplicable:
			if file.AnalysisReason != "" {
				return fmt.Errorf("inventory file %q has a reason for a not-applicable analysis disposition", file.Path)
			}
		case AnalysisAnalyzed:
			if !file.Inspected || file.AnalysisReason != "" {
				return fmt.Errorf("inventory file %q analyzed disposition contradicts inspection metadata", file.Path)
			}
		case AnalysisPartial:
			if !file.Inspected || file.AnalysisReason == "" {
				return fmt.Errorf("inventory file %q partial disposition requires inspected content and a reason", file.Path)
			}
		case AnalysisUnanalyzed:
			if file.AnalysisReason == "" {
				return fmt.Errorf("inventory file %q unanalyzed disposition requires a reason", file.Path)
			}
		default:
			return fmt.Errorf("inventory file %q has invalid analysis disposition %q", file.Path, file.Analysis)
		}
		if file.LinkTarget != "" && file.Kind != "symlink" {
			return fmt.Errorf("inventory file %q has a link target but is not a symlink", file.Path)
		}
		if file.Binary != nil && (!file.Inspected || file.ContentType != "application/x-elf") {
			return fmt.Errorf("inventory file %q has binary metadata without an inspected ELF", file.Path)
		}
		if file.Archive != nil && (!file.Inspected || file.Kind != "regular" || file.Binary != nil) {
			return fmt.Errorf("inventory file %q has archive metadata without an inspected non-ELF regular file", file.Path)
		}
		if archive := file.Archive; archive != nil {
			if !oneOf(archive.Format, "zip", "tar", "gzip", "xz", "zstd", "bzip2") || archive.Entries == nil || archive.RetainedUncompressedBytes < 0 {
				return fmt.Errorf("inventory file %q has incomplete archive metadata", file.Path)
			}
			if len(archive.Entries) > MaxArchiveEntries {
				return fmt.Errorf("inventory file %q archive entries exceed limit %d", file.Path, MaxArchiveEntries)
			}
			var retained int64
			for entryIndex, entry := range archive.Entries {
				if entry.Path == "" || entry.Kind == "" || entry.Size < 0 || entry.CompressedSize < 0 || entry.Size > archive.RetainedUncompressedBytes-retained {
					return fmt.Errorf("inventory file %q archive entry %d is invalid", file.Path, entryIndex)
				}
				retained += entry.Size
			}
			if retained != archive.RetainedUncompressedBytes {
				return fmt.Errorf("inventory file %q archive retained byte total does not match entries", file.Path)
			}
		}
		if binary := file.Binary; binary != nil {
			if binary.Format != "ELF" || binary.Class == "" || binary.ByteOrder == "" || binary.Machine == "" || binary.Type == "" || binary.Libraries == nil || binary.ImportedSymbols == nil || binary.ExtractedStrings == nil || binary.EmbeddedURLs == nil || binary.FileCapabilities == nil {
				return fmt.Errorf("inventory file %q has incomplete ELF metadata", file.Path)
			}
			if len(binary.Libraries) > MaxImportedLibraries {
				return fmt.Errorf("inventory file %q imported libraries exceed limit %d", file.Path, MaxImportedLibraries)
			}
			if len(binary.ImportedSymbols) > MaxImportedSymbols || len(binary.ExtractedStrings) > MaxExtractedStrings || len(binary.EmbeddedURLs) > MaxEmbeddedURLs || len(binary.FileCapabilities) > MaxFileCapabilities {
				return fmt.Errorf("inventory file %q ELF metadata exceeds a collection limit", file.Path)
			}
		}
		if file.Inspected {
			total := &readBytes
			declared := r.Target.ReadBytes
			label := "source"
			if file.ContentType == "application/x-elf" {
				total = &binaryBytes
				declared = r.Target.BinaryBytes
				label = "binary"
			}
			if file.Size > declared-*total {
				return fmt.Errorf("inventory %s bytes exceed target total", label)
			}
			*total += file.Size
		}
	}
	if readBytes != r.Target.ReadBytes || binaryBytes != r.Target.BinaryBytes {
		return fmt.Errorf("target byte totals do not match inspected inventory: source %d/%d, binary %d/%d", r.Target.ReadBytes, readBytes, r.Target.BinaryBytes, binaryBytes)
	}

	operations := make(map[string]struct{}, len(r.Operations))
	referenceKinds := make(map[string]NodeKind, len(r.Operations)+len(r.Resources)+len(r.Findings)+len(r.Unknowns))
	referenceProvenance := make(map[string]Provenance, len(referenceKinds))
	for index, operation := range r.Operations {
		if operation.ID == "" || operation.Reference != publicReference(NodeOperation, operation.ID) || operation.Category == "" || operation.Command == "" {
			return fmt.Errorf("operation %d has no ID, category, or command", index)
		}
		if _, exists := operations[operation.ID]; exists {
			return fmt.Errorf("duplicate operation ID %q", operation.ID)
		}
		operations[operation.ID] = struct{}{}
		if err := addReference(referenceKinds, referenceProvenance, operation.Reference, NodeOperation, operation.Provenance); err != nil {
			return fmt.Errorf("operation %q: %w", operation.ID, err)
		}
		if err := validateProvenance(operation.Provenance, r.Scan.ScannerVersion); err != nil {
			return fmt.Errorf("operation %q: %w", operation.ID, err)
		}
		if len(operation.Arguments) > MaxOperationArguments {
			return fmt.Errorf("operation %q arguments exceed limit %d", operation.ID, MaxOperationArguments)
		}
		if err := validateScopeConfidence(operation.Scope, operation.Confidence); err != nil {
			return fmt.Errorf("operation %q: %w", operation.ID, err)
		}
		if err := validateEvidence(operation.Evidence); err != nil {
			return fmt.Errorf("operation %q: %w", operation.ID, err)
		}
	}
	resources := make(map[string]struct{}, len(r.Resources))
	for _, resource := range r.Resources {
		if resource.ID == "" || resource.Reference != publicReference(NodeResource, resource.ID) || resource.Kind == "" || resource.Access == "" || resource.Value == "" {
			return errors.New("resource identity, kind, access, and value are required")
		}
		if _, exists := resources[resource.ID]; exists {
			return fmt.Errorf("duplicate resource ID %q", resource.ID)
		}
		resources[resource.ID] = struct{}{}
		if err := addReference(referenceKinds, referenceProvenance, resource.Reference, NodeResource, resource.Provenance); err != nil {
			return fmt.Errorf("resource %q: %w", resource.ID, err)
		}
		if err := validateProvenance(resource.Provenance, r.Scan.ScannerVersion); err != nil {
			return fmt.Errorf("resource %q: %w", resource.ID, err)
		}
		if err := validateScopeConfidence(resource.Scope, resource.Confidence); err != nil {
			return fmt.Errorf("resource %q: %w", resource.ID, err)
		}
		if err := validateEvidence(resource.Evidence); err != nil {
			return fmt.Errorf("resource %q: %w", resource.ID, err)
		}
		if resource.RelatedOperationID == "" {
			return fmt.Errorf("resource %q has no originating operation", resource.ID)
		}
		if _, exists := operations[resource.RelatedOperationID]; !exists {
			return fmt.Errorf("resource %q references missing operation %q", resource.ID, resource.RelatedOperationID)
		}
	}
	findings := make(map[string]struct{}, len(r.Findings))
	for _, finding := range r.Findings {
		if finding.ID == "" || finding.Reference != publicReference(NodeFinding, finding.ID) || finding.Category == "" || finding.Title == "" || finding.Explanation == "" {
			return errors.New("finding identity, category, title, explanation, and provenance are required")
		}
		if _, exists := findings[finding.ID]; exists {
			return fmt.Errorf("duplicate finding ID %q", finding.ID)
		}
		findings[finding.ID] = struct{}{}
		if err := addReference(referenceKinds, referenceProvenance, finding.Reference, NodeFinding, finding.Provenance); err != nil {
			return fmt.Errorf("finding %q: %w", finding.ID, err)
		}
		if err := validateProvenance(finding.Provenance, r.Scan.ScannerVersion); err != nil {
			return fmt.Errorf("finding %q: %w", finding.ID, err)
		}
		if len(finding.Evidence) == 0 {
			return fmt.Errorf("finding %q has no evidence", finding.ID)
		}
		if len(finding.Evidence) > MaxFindingEvidence || len(finding.Related) > MaxFindingRelated {
			return fmt.Errorf("finding %q evidence or relationships exceed structural limits", finding.ID)
		}
		if !oneOf(string(finding.Claim), string(ClaimFact), string(ClaimInference)) {
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
		if finding.Claim == ClaimInference && len(finding.Related) == 0 {
			return fmt.Errorf("inference %q has no declared supporting operation", finding.ID)
		}
		if duplicateString(finding.Related) {
			return fmt.Errorf("finding %q repeats a supporting operation", finding.ID)
		}
	}
	unknowns := make(map[string]struct{}, len(r.Unknowns))
	for _, unknown := range r.Unknowns {
		if unknown.ID == "" || unknown.Reference != publicReference(NodeUnknown, unknown.ID) || unknown.Category == "" || unknown.Title == "" || unknown.Description == "" {
			return errors.New("unknown identity, category, title, description, and public reference are required")
		}
		if _, exists := unknowns[unknown.ID]; exists {
			return fmt.Errorf("duplicate unknown ID %q", unknown.ID)
		}
		unknowns[unknown.ID] = struct{}{}
		if err := addReference(referenceKinds, referenceProvenance, unknown.Reference, NodeUnknown, unknown.Provenance); err != nil {
			return fmt.Errorf("unknown %q: %w", unknown.ID, err)
		}
		if err := validateProvenance(unknown.Provenance, r.Scan.ScannerVersion); err != nil {
			return fmt.Errorf("unknown %q: %w", unknown.ID, err)
		}
		if !oneOf(string(unknown.Reason), string(UnknownDynamicValue), string(UnknownUnsupportedSyntax), string(UnknownParserFailure), string(UnknownBudgetExhaustion), string(UnknownUnreachableSource), string(UnknownNativeBehavior), string(UnknownUnresolvedFlow)) {
			return fmt.Errorf("unknown %q has invalid reason %q", unknown.ID, unknown.Reason)
		}
		if err := validateScopeConfidence(unknown.Scope, unknown.Confidence); err != nil {
			return fmt.Errorf("unknown %q: %w", unknown.ID, err)
		}
		if len(unknown.Evidence) == 0 || len(unknown.Evidence) > MaxUnknownEvidence || len(unknown.Origins) > MaxUnknownOrigins ||
			len(unknown.AffectedOperations) > MaxUnknownAffected || len(unknown.SuppressedRules) > MaxUnknownSuppressed {
			return fmt.Errorf("unknown %q evidence, origins, affected operations, or suppressed rules exceed structural requirements", unknown.ID)
		}
		if unknown.Origins == nil || unknown.AffectedOperations == nil || unknown.SuppressedRules == nil {
			return fmt.Errorf("unknown %q origin, affected-operation, and suppressed-rule collections must be JSON arrays", unknown.ID)
		}
		for _, evidence := range unknown.Evidence {
			if err := validateEvidence(evidence); err != nil {
				return fmt.Errorf("unknown %q: %w", unknown.ID, err)
			}
		}
		for _, origin := range unknown.Origins {
			if !oneOf(string(origin.Kind), string(OriginAssignment), string(OriginParameterExpansion), string(OriginPropertyAssignment), string(OriginUseSite)) {
				return fmt.Errorf("unknown %q has invalid origin kind %q", unknown.ID, origin.Kind)
			}
			if err := validateEvidence(origin.Evidence); err != nil {
				return fmt.Errorf("unknown %q origin: %w", unknown.ID, err)
			}
		}
		seenAffected := make(map[string]bool, len(unknown.AffectedOperations))
		for _, affected := range unknown.AffectedOperations {
			if _, exists := operations[affected]; !exists {
				return fmt.Errorf("unknown %q references missing operation %q", unknown.ID, affected)
			}
			if seenAffected[affected] {
				return fmt.Errorf("unknown %q repeats affected operation %q", unknown.ID, affected)
			}
			seenAffected[affected] = true
		}
	}
	if err := validateRelationships(r, referenceKinds, referenceProvenance); err != nil {
		return err
	}
	for index, limitation := range r.Limitations {
		if limitation.Code == "" || limitation.Description == "" {
			return fmt.Errorf("limitation %d has no code or description", index)
		}
		if limitation.Path != "" {
			if err := validateRelativePath(limitation.Path); err != nil {
				return fmt.Errorf("limitation %d: %w", index, err)
			}
		}
		if limitation.Scope != "" && !oneOf(string(limitation.Scope), string(ScopeRuntime), string(ScopeTooling), string(ScopeUnknown)) {
			return fmt.Errorf("limitation %d has invalid scope %q", index, limitation.Scope)
		}
	}
	for index, scanError := range r.Errors {
		if scanError.Code == "" || scanError.Message == "" {
			return fmt.Errorf("scan error %d has no code or message", index)
		}
		if scanError.Path != "" {
			if err := validateRelativePath(scanError.Path); err != nil {
				return fmt.Errorf("scan error %d: %w", index, err)
			}
		}
	}
	if err := validateReviewSummary(r); err != nil {
		return err
	}
	if err := validateHostileStrings(r); err != nil {
		return err
	}
	switch r.Status {
	case StatusComplete:
		if len(r.Unknowns) != 0 || len(r.Limitations) != 0 || len(r.Errors) != 0 {
			return errors.New("complete report cannot contain unknowns, limitations, or scan errors")
		}
		if r.Review.AnalysisCoverage.Level != "complete" && r.Review.AnalysisCoverage.Level != "not-applicable" {
			return errors.New("complete report requires complete analysis coverage")
		}
	case StatusIncomplete:
		if len(r.Unknowns) == 0 && len(r.Limitations) == 0 && len(r.Errors) == 0 {
			return errors.New("incomplete report must explain itself with an unknown, limitation, or scan error")
		}
	case StatusError:
		if len(r.Errors) == 0 {
			return errors.New("error report must contain a scan error")
		}
	}
	return nil
}

func validateHostileStrings(r Report) error {
	check := func(label, value string) error {
		encoded, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("%s cannot be JSON encoded: %w", label, err)
		}
		if len(encoded) > MaxHostileStringBytes {
			return fmt.Errorf("%s encoded length exceeds limit %d", label, MaxHostileStringBytes)
		}
		return nil
	}
	if err := validateEveryReportString(reflect.ValueOf(r), "report", check); err != nil {
		return err
	}
	values := []struct{ label, value string }{{"target display name", r.Target.DisplayName}}
	if review := r.Review; review != nil {
		values = append(values, struct{ label, value string }{"coverage denominator", review.AnalysisCoverage.Denominator})
		for _, collection := range [][]ReviewReason{review.SecurityImpact.Reasons, review.EvidenceConfidence.Reasons, review.UnknownBehavior.Reasons, review.MainReasons} {
			for _, reason := range collection {
				values = append(values, struct{ label, value string }{"review reason reference", reason.Reference}, struct{ label, value string }{"review reason title", reason.Title})
			}
		}
	}
	if manifest := r.Target.Manifest; manifest != nil {
		values = append(values, struct{ label, value string }{"manifest ID", manifest.ID}, struct{ label, value string }{"manifest name", manifest.Name}, struct{ label, value string }{"manifest version", manifest.Version}, struct{ label, value string }{"manifest description", manifest.Description})
		for _, value := range manifest.Kinds {
			values = append(values, struct{ label, value string }{"manifest kind", value})
		}
		for key, value := range manifest.EntryPoints {
			values = append(values, struct{ label, value string }{"manifest entry-point key", key}, struct{ label, value string }{"manifest entry-point value", value})
		}
	}
	for _, file := range r.Inventory {
		values = append(values, struct{ label, value string }{"inventory path", file.Path}, struct{ label, value string }{"link target", file.LinkTarget})
		if file.Binary != nil {
			values = append(values, struct{ label, value string }{"ELF interpreter", file.Binary.Interpreter})
			for _, value := range file.Binary.Libraries {
				values = append(values, struct{ label, value string }{"ELF library", value})
			}
			for _, collection := range [][]string{file.Binary.ImportedSymbols, file.Binary.ExtractedStrings, file.Binary.EmbeddedURLs, file.Binary.FileCapabilities} {
				for _, value := range collection {
					values = append(values, struct{ label, value string }{"ELF metadata", value})
				}
			}
		}
		if file.Archive != nil {
			values = append(values, struct{ label, value string }{"archive format", file.Archive.Format})
			for _, entry := range file.Archive.Entries {
				values = append(values, struct{ label, value string }{"archive entry path", entry.Path}, struct{ label, value string }{"archive entry kind", entry.Kind}, struct{ label, value string }{"archive entry mode", entry.Mode}, struct{ label, value string }{"archive link target", entry.LinkTarget})
			}
		}
	}
	for _, operation := range r.Operations {
		values = append(values, struct{ label, value string }{"operation command", operation.Command}, struct{ label, value string }{"operation evidence", operation.Evidence.Operation}, struct{ label, value string }{"operation excerpt", operation.Evidence.Excerpt},
			struct{ label, value string }{"operation rule ID", operation.Provenance.RuleID}, struct{ label, value string }{"operation analyzer", operation.Provenance.Analyzer}, struct{ label, value string }{"operation analyzer version", operation.Provenance.AnalyzerVersion})
		for _, value := range operation.Arguments {
			values = append(values, struct{ label, value string }{"operation argument", value})
		}
	}
	for _, resource := range r.Resources {
		values = append(values, struct{ label, value string }{"resource value", resource.Value}, struct{ label, value string }{"resource evidence", resource.Evidence.Operation}, struct{ label, value string }{"resource excerpt", resource.Evidence.Excerpt},
			struct{ label, value string }{"resource rule ID", resource.Provenance.RuleID}, struct{ label, value string }{"resource analyzer", resource.Provenance.Analyzer}, struct{ label, value string }{"resource analyzer version", resource.Provenance.AnalyzerVersion})
	}
	for _, finding := range r.Findings {
		values = append(values, struct{ label, value string }{"finding title", finding.Title}, struct{ label, value string }{"finding explanation", finding.Explanation},
			struct{ label, value string }{"finding rule ID", finding.Provenance.RuleID}, struct{ label, value string }{"finding analyzer", finding.Provenance.Analyzer}, struct{ label, value string }{"finding analyzer version", finding.Provenance.AnalyzerVersion})
		for _, evidence := range finding.Evidence {
			values = append(values, struct{ label, value string }{"finding evidence", evidence.Operation}, struct{ label, value string }{"finding excerpt", evidence.Excerpt})
		}
	}
	for _, unknown := range r.Unknowns {
		values = append(values, struct{ label, value string }{"unknown category", unknown.Category}, struct{ label, value string }{"unknown title", unknown.Title}, struct{ label, value string }{"unknown description", unknown.Description},
			struct{ label, value string }{"unknown rule ID", unknown.Provenance.RuleID}, struct{ label, value string }{"unknown analyzer", unknown.Provenance.Analyzer}, struct{ label, value string }{"unknown analyzer version", unknown.Provenance.AnalyzerVersion})
		for _, evidence := range unknown.Evidence {
			values = append(values, struct{ label, value string }{"unknown evidence", evidence.Operation}, struct{ label, value string }{"unknown excerpt", evidence.Excerpt})
		}
		for _, origin := range unknown.Origins {
			values = append(values, struct{ label, value string }{"unknown origin name", origin.Name}, struct{ label, value string }{"unknown origin evidence", origin.Evidence.Operation}, struct{ label, value string }{"unknown origin excerpt", origin.Evidence.Excerpt})
		}
		for _, rule := range unknown.SuppressedRules {
			values = append(values, struct{ label, value string }{"unknown suppressed rule", rule})
		}
	}
	for _, limitation := range r.Limitations {
		values = append(values, struct{ label, value string }{"limitation description", limitation.Description}, struct{ label, value string }{"limitation path", limitation.Path})
	}
	for _, scanError := range r.Errors {
		values = append(values, struct{ label, value string }{"scan error message", scanError.Message}, struct{ label, value string }{"scan error path", scanError.Path})
	}
	for _, value := range values {
		if err := check(value.label, value.value); err != nil {
			return err
		}
	}
	return nil
}

func validateEveryReportString(value reflect.Value, label string, check func(string, string) error) error {
	if !value.IsValid() {
		return nil
	}
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		return validateEveryReportString(value.Elem(), label, check)
	}
	switch value.Kind() {
	case reflect.String:
		return check(label, value.String())
	case reflect.Struct:
		typeInfo := value.Type()
		for index := 0; index < value.NumField(); index++ {
			if typeInfo.Field(index).PkgPath != "" {
				continue
			}
			if err := validateEveryReportString(value.Field(index), label+"."+typeInfo.Field(index).Name, check); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for index := 0; index < value.Len(); index++ {
			if err := validateEveryReportString(value.Index(index), label, check); err != nil {
				return err
			}
		}
	case reflect.Map:
		iterator := value.MapRange()
		for iterator.Next() {
			if err := validateEveryReportString(iterator.Key(), label+" key", check); err != nil {
				return err
			}
			if err := validateEveryReportString(iterator.Value(), label+" value", check); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateCollectionBounds(r Report) error {
	collections := []struct {
		name  string
		count int
		limit int
	}{
		{"inventory", len(r.Inventory), MaxInventoryEntries},
		{"operations", len(r.Operations), MaxOperationEntries},
		{"resources", len(r.Resources), MaxResourceEntries},
		{"findings", len(r.Findings), MaxFindingEntries},
		{"unknowns", len(r.Unknowns), MaxUnknownEntries},
		{"relationships", len(r.Relationships), MaxEvidenceRelations},
		{"limitations", len(r.Limitations), MaxLimitationEntries},
		{"errors", len(r.Errors), MaxErrorEntries},
	}
	for _, collection := range collections {
		if collection.count > collection.limit {
			return fmt.Errorf("report %s count %d exceeds limit %d", collection.name, collection.count, collection.limit)
		}
	}
	return nil
}

func addReference(kinds map[string]NodeKind, provenance map[string]Provenance, reference string, kind NodeKind, value Provenance) error {
	if reference == "" {
		return errors.New("public evidence reference is required")
	}
	if previous, exists := kinds[reference]; exists {
		return fmt.Errorf("duplicate public evidence reference %q for %s and %s", reference, previous, kind)
	}
	kinds[reference] = kind
	provenance[reference] = value
	return nil
}

func validateProvenance(value Provenance, scannerVersion string) error {
	if value.RuleID == "" || value.Analyzer == "" || value.AnalyzerVersion == "" {
		return errors.New("rule ID, analyzer, and analyzer version provenance are required")
	}
	if !oneOf(string(value.EvidenceSource), string(EvidenceSourceTargetSource), string(EvidenceSourceInventoryMetadata), string(EvidenceSourceOmarchyAudit)) {
		return fmt.Errorf("invalid evidence source %q", value.EvidenceSource)
	}
	switch value.EvidenceSource {
	case EvidenceSourceTargetSource, EvidenceSourceInventoryMetadata:
		if value.Analyzer != "plug-prejudice/deterministic" || value.AnalyzerVersion != scannerVersion {
			return errors.New("local evidence provenance does not match the trusted scanner identity")
		}
	case EvidenceSourceOmarchyAudit:
		if value.Analyzer != "omarchy/plugin-audit" {
			return errors.New("Omarchy evidence provenance has an invalid analyzer identity")
		}
	}
	return nil
}

func duplicateString(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func validateRelationships(r Report, kinds map[string]NodeKind, provenance map[string]Provenance) error {
	required := make(map[string]bool, len(r.Resources)+len(r.Findings)*2)
	operationReferences := make(map[string]string, len(r.Operations))
	for _, operation := range r.Operations {
		operationReferences[operation.ID] = operation.Reference
	}
	for _, resource := range r.Resources {
		required[relationshipID(RelationshipDerivedFrom, NodeResource, resource.Reference, NodeOperation, operationReferences[resource.RelatedOperationID])] = false
	}
	for _, finding := range r.Findings {
		kind := RelationshipEstablishedBy
		if finding.Claim == ClaimInference {
			kind = RelationshipInferredFrom
		}
		for _, related := range finding.Related {
			required[relationshipID(kind, NodeFinding, finding.Reference, NodeOperation, operationReferences[related])] = false
		}
	}
	for _, unknown := range r.Unknowns {
		for _, affected := range unknown.AffectedOperations {
			required[relationshipID(RelationshipUnknownBecause, NodeUnknown, unknown.Reference, NodeOperation, operationReferences[affected])] = false
		}
	}

	seen := make(map[string]bool, len(r.Relationships))
	comparisonPairs := make(map[string]RelationshipType)
	for _, relationship := range r.Relationships {
		if relationship.ID == "" || relationship.From == "" || relationship.To == "" || relationship.From == relationship.To {
			return errors.New("relationship identity and distinct endpoints are required")
		}
		if seen[relationship.ID] {
			return fmt.Errorf("duplicate relationship ID %q", relationship.ID)
		}
		seen[relationship.ID] = true
		if kinds[relationship.From] != relationship.FromKind || kinds[relationship.To] != relationship.ToKind {
			return fmt.Errorf("relationship %q has missing or incorrectly typed endpoints", relationship.ID)
		}
		if relationship.ID != relationshipID(relationship.Type, relationship.FromKind, relationship.From, relationship.ToKind, relationship.To) {
			return fmt.Errorf("relationship %q does not match its typed endpoints", relationship.ID)
		}
		switch relationship.Type {
		case RelationshipDerivedFrom:
			if relationship.FromKind != NodeResource || relationship.ToKind != NodeOperation {
				return fmt.Errorf("relationship %q has invalid derived-from endpoint types", relationship.ID)
			}
			if _, requiredBaseEdge := required[relationship.ID]; !requiredBaseEdge {
				return fmt.Errorf("relationship %q is not the resource's declared origin", relationship.ID)
			}
		case RelationshipEstablishedBy, RelationshipInferredFrom:
			if relationship.FromKind != NodeFinding || relationship.ToKind != NodeOperation {
				return fmt.Errorf("relationship %q has invalid finding-support endpoint types", relationship.ID)
			}
			if _, requiredBaseEdge := required[relationship.ID]; !requiredBaseEdge {
				return fmt.Errorf("relationship %q does not match the finding's claim or declared support", relationship.ID)
			}
		case RelationshipUnknownBecause:
			if (relationship.FromKind != NodeFinding && relationship.FromKind != NodeUnknown) || relationship.ToKind != NodeOperation {
				return fmt.Errorf("relationship %q has invalid unknown-support endpoint types", relationship.ID)
			}
			if _, requiredBaseEdge := required[relationship.ID]; !requiredBaseEdge {
				return fmt.Errorf("relationship %q does not match the unknown's declared affected operation", relationship.ID)
			}
		case RelationshipCorroborates, RelationshipDisagreesWith:
			if relationship.From > relationship.To {
				return fmt.Errorf("relationship %q comparison endpoints are not canonical", relationship.ID)
			}
			if provenance[relationship.From].EvidenceSource == provenance[relationship.To].EvidenceSource {
				return fmt.Errorf("relationship %q claims independent evidence from the same source", relationship.ID)
			}
			pair := relationship.From + "\x00" + relationship.To
			if previous, exists := comparisonPairs[pair]; exists {
				return fmt.Errorf("relationship %q conflicts with existing %s comparison", relationship.ID, previous)
			}
			comparisonPairs[pair] = relationship.Type
		case RelationshipDuplicates:
			if relationship.From > relationship.To {
				return fmt.Errorf("relationship %q duplicate endpoints are not canonical", relationship.ID)
			}
			if provenance[relationship.From].EvidenceSource != provenance[relationship.To].EvidenceSource {
				return fmt.Errorf("relationship %q calls observations from different sources duplicates", relationship.ID)
			}
			pair := relationship.From + "\x00" + relationship.To
			if previous, exists := comparisonPairs[pair]; exists {
				return fmt.Errorf("relationship %q conflicts with existing %s comparison", relationship.ID, previous)
			}
			comparisonPairs[pair] = relationship.Type
		default:
			return fmt.Errorf("relationship %q has invalid type %q", relationship.ID, relationship.Type)
		}
		if _, exists := required[relationship.ID]; exists {
			required[relationship.ID] = true
		}
	}
	for id, present := range required {
		if !present {
			return fmt.Errorf("required evidence relationship %q is missing", id)
		}
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
	if err := validateRelativePath(evidence.Path); err != nil {
		return err
	}
	if evidence.LineStart < 0 || evidence.LineEnd < 0 ||
		(evidence.LineStart == 0 && evidence.LineEnd != 0) ||
		(evidence.LineEnd != 0 && evidence.LineEnd < evidence.LineStart) {
		return fmt.Errorf("invalid evidence lines for %q", evidence.Path)
	}
	return nil
}

func validateRelativePath(value string) error {
	if strings.Contains(value, "\\") {
		return fmt.Errorf("noncanonical target-relative path %q", value)
	}
	clean := path.Clean(value)
	if clean != value || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return fmt.Errorf("unsafe target-relative path %q", value)
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
