package report

import "time"

const SchemaVersion = "2.0.0"

const (
	TargetEvidenceInputID      = "input-target"
	TargetEvidenceInputFormat  = "plug-prejudice-inventory"
	TargetEvidenceInputVersion = SchemaVersion

	OmarchyAuditInputFormat         = "omarchy-plugin-audit"
	OmarchyAuditInputVersion        = "pr8439-732b104"
	OmarchyAuditAnalyzer            = "omarchy/plugin-audit"
	ExternalEvidenceBindingCategory = "external-evidence-binding"
	ExternalSnapshotBindingRule     = "external-snapshot-equivalence/v1"
	OmarchyAuditObservationRule     = "omarchy-audit-observation/v1"
	CoverageDifferenceCategory      = "omarchy-audit-coverage-disagreement"
	CoverageComparisonRule          = "omarchy-audit-coverage-comparison/v1"
)

// Collection limits bound the validated object graph handed to presentation
// consumers. The inventory limit matches the scanner's default file ceiling;
// derived collections allow multiple observations per file without accepting
// an effectively unbounded graph from a compromised producer.
const (
	MaxInventoryEntries          = 10_000
	MaxOperationEntries          = 20_000
	MaxResourceEntries           = 20_000
	MaxFindingEntries            = 20_000
	MaxUnknownEntries            = 20_000
	MaxLimitationEntries         = 20_000
	MaxErrorEntries              = 10_000
	MaxOperationArguments        = 1_024
	MaxManifestKinds             = 128
	MaxManifestEntryPoints       = 128
	MaxImportedLibraries         = 1_024
	MaxImportedSymbols           = 1_024
	MaxExtractedStrings          = 256
	MaxEmbeddedURLs              = 128
	MaxFileCapabilities          = 64
	MaxArchiveEntries            = 4_096
	MaxFindingEvidence           = 8
	MaxFindingRelated            = 16
	MaxUnknownEvidence           = 8
	MaxUnknownAffected           = 16
	MaxUnknownOrigins            = 8
	MaxUnknownSuppressed         = 16
	MaxComparisonRelations       = 20_000
	MaxEvidenceInputs            = 16
	MaxEvidenceRelations         = MaxResourceEntries + MaxFindingEntries*MaxFindingRelated + MaxUnknownEntries*MaxUnknownAffected + MaxComparisonRelations
	MaxProducedEvidenceRelations = 20_000
	MaxHostileStringBytes        = 4 << 10
	MaxEncodedReportBytes        = 16 << 20
	MaxJSONDepth                 = 64
)

type ClaimType string

const (
	ClaimFact      ClaimType = "fact"
	ClaimInference ClaimType = "inference"
)

type Severity string

const (
	SeverityCritical      Severity = "critical"
	SeverityHigh          Severity = "high"
	SeverityMedium        Severity = "medium"
	SeverityLow           Severity = "low"
	SeverityInformational Severity = "informational"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type Scope string

const (
	ScopeRuntime Scope = "runtime"
	ScopeTooling Scope = "repository-tooling"
	ScopeUnknown Scope = "unknown"
)

type Status string

const (
	StatusComplete   Status = "complete"
	StatusIncomplete Status = "incomplete"
	StatusError      Status = "error"
)

type Report struct {
	SchemaVersion  string          `json:"schemaVersion"`
	Status         Status          `json:"status"`
	Scan           ScanMetadata    `json:"scan"`
	Target         Target          `json:"target"`
	EvidenceInputs []EvidenceInput `json:"evidenceInputs"`
	Review         *ReviewSummary  `json:"review"`
	Inventory      []File          `json:"inventory"`
	Operations     []Operation     `json:"operations"`
	Resources      []Resource      `json:"resources"`
	Findings       []Finding       `json:"findings"`
	Unknowns       []Unknown       `json:"unknowns"`
	Relationships  []Relationship  `json:"relationships"`
	Limitations    []Limitation    `json:"limitations"`
	Errors         []ScanError     `json:"errors"`
}

const CoverageDenominator = "retained supported executable, configuration, archive, and binary artifact files"

type ReviewSummary struct {
	SecurityImpact     ImpactSummary     `json:"securityImpact"`
	EvidenceConfidence ConfidenceSummary `json:"evidenceConfidence"`
	AnalysisCoverage   CoverageSummary   `json:"analysisCoverage"`
	UnknownBehavior    UnknownSummary    `json:"unknownBehavior"`
	Counts             ClaimCounts       `json:"counts"`
	MainReasons        []ReviewReason    `json:"mainReasons"`
}

type ReviewReason struct {
	Reference string `json:"reference,omitempty"`
	Title     string `json:"title"`
	Scope     Scope  `json:"scope,omitempty"`
}
type ImpactSummary struct {
	Level   Severity       `json:"level"`
	Reasons []ReviewReason `json:"reasons"`
}
type ConfidenceSummary struct {
	Level   string         `json:"level"`
	High    int            `json:"high"`
	Medium  int            `json:"medium"`
	Low     int            `json:"low"`
	Reasons []ReviewReason `json:"reasons"`
}
type CoverageSummary struct {
	Level           string `json:"level"`
	Denominator     string `json:"denominator"`
	AnalyzedUnits   int    `json:"analyzedUnits"`
	PartialUnits    int    `json:"partialUnits"`
	UnanalyzedUnits int    `json:"unanalyzedUnits"`
	ExcludedUnits   int    `json:"excludedUnits"`
	TotalUnits      int    `json:"totalUnits"`
	RetainedUnits   int    `json:"retainedUnits"`
	Percentage      *int   `json:"percentage"`
}
type UnknownSummary struct {
	Level       string         `json:"level"`
	Unknowns    int            `json:"unknowns"`
	Limitations int            `json:"limitations"`
	Errors      int            `json:"errors"`
	Reasons     []ReviewReason `json:"reasons"`
}
type ClaimCounts struct {
	Facts            int `json:"facts"`
	Inferences       int `json:"inferences"`
	UnknownBehaviors int `json:"unknownBehaviors"`
}

type ScanMetadata struct {
	ScannerVersion string          `json:"scannerVersion"`
	PolicyVersion  string          `json:"policyVersion"`
	StartedAt      time.Time       `json:"startedAt"`
	CompletedAt    time.Time       `json:"completedAt"`
	Sandboxed      bool            `json:"sandboxed"`
	ResourceLimits *ResourceLimits `json:"resourceLimits,omitempty"`
}

type ResourceLimits struct {
	MemoryMaxBytes  int64 `json:"memoryMaxBytes"`
	MemorySwapBytes int64 `json:"memorySwapBytes"`
	TasksMax        int   `json:"tasksMax"`
	CPUQuotaPercent int   `json:"cpuQuotaPercent"`
	WallTimeSeconds int   `json:"wallTimeSeconds"`
}

type Target struct {
	DisplayName string    `json:"displayName"`
	RootDigest  string    `json:"rootDigest,omitempty"`
	FileCount   int       `json:"fileCount"`
	ReadBytes   int64     `json:"readBytes"`
	BinaryBytes int64     `json:"binaryBytes"`
	Manifest    *Manifest `json:"manifest,omitempty"`
}

type Manifest struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Description string            `json:"description,omitempty"`
	Kinds       []string          `json:"kinds"`
	EntryPoints map[string]string `json:"entryPoints"`
}

type File struct {
	Path           string              `json:"path"`
	Kind           string              `json:"kind"`
	Mode           string              `json:"mode"`
	Size           int64               `json:"size"`
	SHA256         string              `json:"sha256,omitempty"`
	ContentType    string              `json:"contentType,omitempty"`
	LinkTarget     string              `json:"linkTarget,omitempty"`
	Inspected      bool                `json:"inspected"`
	SkipReason     string              `json:"skipReason,omitempty"`
	Analysis       AnalysisDisposition `json:"analysis"`
	AnalysisReason string              `json:"analysisReason,omitempty"`
	Binary         *Binary             `json:"binary,omitempty"`
	Archive        *Archive            `json:"archive,omitempty"`
}

type AnalysisDisposition string

const (
	AnalysisNotApplicable AnalysisDisposition = "not-applicable"
	AnalysisAnalyzed      AnalysisDisposition = "analyzed"
	AnalysisPartial       AnalysisDisposition = "partial"
	AnalysisUnanalyzed    AnalysisDisposition = "unanalyzed"
)

type Binary struct {
	Format              string   `json:"format"`
	Class               string   `json:"class"`
	ByteOrder           string   `json:"byteOrder"`
	Machine             string   `json:"machine"`
	Type                string   `json:"type"`
	Interpreter         string   `json:"interpreter,omitempty"`
	Libraries           []string `json:"libraries"`
	ImportedSymbols     []string `json:"importedSymbols"`
	ExtractedStrings    []string `json:"extractedStrings"`
	EmbeddedURLs        []string `json:"embeddedUrls"`
	FileCapabilities    []string `json:"fileCapabilities"`
	CapabilityEffective bool     `json:"capabilityEffective"`
	SetUID              bool     `json:"setuid"`
	SetGID              bool     `json:"setgid"`
	HasSymbols          bool     `json:"hasSymbols"`
}

type Archive struct {
	Format                    string         `json:"format"`
	Entries                   []ArchiveEntry `json:"entries"`
	InventoryComplete         bool           `json:"inventoryComplete"`
	RetainedUncompressedBytes int64          `json:"retainedUncompressedBytes"`
}

type ArchiveEntry struct {
	Path           string `json:"path"`
	Kind           string `json:"kind"`
	Mode           string `json:"mode,omitempty"`
	LinkTarget     string `json:"linkTarget,omitempty"`
	Size           int64  `json:"size"`
	CompressedSize int64  `json:"compressedSize,omitempty"`
	UnsafePath     bool   `json:"unsafePath"`
	Encrypted      bool   `json:"encrypted,omitempty"`
}

type Operation struct {
	ID         string     `json:"id"`
	Reference  string     `json:"reference"`
	Category   string     `json:"category"`
	Scope      Scope      `json:"scope"`
	Command    string     `json:"command,omitempty"`
	Arguments  []string   `json:"arguments,omitempty"`
	Dynamic    bool       `json:"dynamic"`
	Confidence Confidence `json:"confidence"`
	Evidence   Evidence   `json:"evidence"`
	Provenance Provenance `json:"provenance"`
}

type Resource struct {
	ID                 string     `json:"id"`
	Reference          string     `json:"reference"`
	Kind               string     `json:"kind"`
	Access             string     `json:"access"`
	Value              string     `json:"value"`
	Sensitive          bool       `json:"sensitive"`
	Dynamic            bool       `json:"dynamic"`
	Scope              Scope      `json:"scope"`
	Confidence         Confidence `json:"confidence"`
	Evidence           Evidence   `json:"evidence"`
	RelatedOperationID string     `json:"relatedOperationId"`
	Provenance         Provenance `json:"provenance"`
}

type Finding struct {
	ID          string     `json:"id"`
	Reference   string     `json:"reference"`
	Claim       ClaimType  `json:"claim"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	Category    string     `json:"category"`
	Scope       Scope      `json:"scope"`
	Title       string     `json:"title"`
	Explanation string     `json:"explanation"`
	Evidence    []Evidence `json:"evidence"`
	Related     []string   `json:"relatedOperationIds,omitempty"`
	Provenance  Provenance `json:"provenance"`
}

type UnknownReason string

const (
	UnknownDynamicValue      UnknownReason = "dynamic-value"
	UnknownUnsupportedSyntax UnknownReason = "unsupported-syntax"
	UnknownParserFailure     UnknownReason = "parser-failure"
	UnknownBudgetExhaustion  UnknownReason = "budget-exhaustion"
	UnknownUnreachableSource UnknownReason = "unreachable-source"
	UnknownNativeBehavior    UnknownReason = "native-behavior"
	UnknownUnresolvedFlow    UnknownReason = "unresolved-data-flow"
	UnknownExternalBinding   UnknownReason = "external-input-unbound"
)

type OriginKind string

const (
	OriginAssignment         OriginKind = "assignment"
	OriginParameterExpansion OriginKind = "parameter-expansion"
	OriginPropertyAssignment OriginKind = "property-assignment"
	OriginUseSite            OriginKind = "use-site"
)

type ValueOrigin struct {
	Kind     OriginKind `json:"kind"`
	Name     string     `json:"name,omitempty"`
	Evidence Evidence   `json:"evidence"`
}

type Unknown struct {
	ID                 string        `json:"id"`
	Reference          string        `json:"reference"`
	Category           string        `json:"category"`
	Reason             UnknownReason `json:"reason"`
	Scope              Scope         `json:"scope"`
	Confidence         Confidence    `json:"confidence"`
	Title              string        `json:"title"`
	Description        string        `json:"description"`
	Evidence           []Evidence    `json:"evidence"`
	Origins            []ValueOrigin `json:"origins"`
	AffectedOperations []string      `json:"affectedOperationIds"`
	SuppressedRules    []string      `json:"suppressedRuleIds"`
	Provenance         Provenance    `json:"provenance"`
}

type EvidenceSource string

const (
	EvidenceSourceTargetSource      EvidenceSource = "target-source"
	EvidenceSourceInventoryMetadata EvidenceSource = "inventory-metadata"
	EvidenceSourceOmarchyAudit      EvidenceSource = "omarchy-audit"
)

type Provenance struct {
	RuleID          string         `json:"ruleId"`
	Analyzer        string         `json:"analyzer"`
	AnalyzerVersion string         `json:"analyzerVersion"`
	EvidenceSource  EvidenceSource `json:"evidenceSource"`
}

type NodeKind string

const (
	NodeOperation NodeKind = "operation"
	NodeResource  NodeKind = "resource"
	NodeFinding   NodeKind = "finding"
	NodeUnknown   NodeKind = "unknown"
)

type RelationshipType string

const (
	RelationshipDerivedFrom    RelationshipType = "derived-from"
	RelationshipEstablishedBy  RelationshipType = "established-by"
	RelationshipInferredFrom   RelationshipType = "inferred-from"
	RelationshipUnknownBecause RelationshipType = "unknown-because"
	RelationshipCorroborates   RelationshipType = "corroborates"
	RelationshipDisagreesWith  RelationshipType = "disagrees-with"
	RelationshipDuplicates     RelationshipType = "duplicates"
)

type Relationship struct {
	ID         string           `json:"id"`
	Type       RelationshipType `json:"type"`
	FromKind   NodeKind         `json:"fromKind"`
	From       string           `json:"from"`
	ToKind     NodeKind         `json:"toKind"`
	To         string           `json:"to"`
	Comparison *ComparisonBasis `json:"comparison,omitempty"`
}

type Evidence struct {
	InputID   string `json:"inputId"`
	Path      string `json:"path"`
	LineStart int    `json:"lineStart,omitempty"`
	LineEnd   int    `json:"lineEnd,omitempty"`
	Operation string `json:"operation,omitempty"`
	Excerpt   string `json:"excerpt,omitempty"`
}

type EvidenceInputType string

const (
	EvidenceInputTarget       EvidenceInputType = "target-inventory"
	EvidenceInputOmarchyAudit EvidenceInputType = "omarchy-audit"
)

type EvidenceInput struct {
	ID                string            `json:"id"`
	Type              EvidenceInputType `json:"type"`
	Label             string            `json:"label"`
	DocumentSHA256    string            `json:"documentSha256,omitempty"`
	SubjectRootDigest string            `json:"subjectRootDigest,omitempty"`
	Format            string            `json:"format"`
	Version           string            `json:"version"`
}

type ComparisonBasis struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
}

type Limitation struct {
	Code        string `json:"code"`
	Description string `json:"description"`
	Path        string `json:"path,omitempty"`
	Scope       Scope  `json:"scope,omitempty"`
}

type ScanError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Path    string `json:"path,omitempty"`
}
