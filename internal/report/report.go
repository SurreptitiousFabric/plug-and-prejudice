package report

import "time"

const SchemaVersion = "1.0.0"

type ClaimType string

const (
	ClaimFact      ClaimType = "fact"
	ClaimInference ClaimType = "inference"
	ClaimUnknown   ClaimType = "unknown"
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
	SchemaVersion string       `json:"schemaVersion"`
	Status        Status       `json:"status"`
	Scan          ScanMetadata `json:"scan"`
	Target        Target       `json:"target"`
	Inventory     []File       `json:"inventory"`
	Operations    []Operation  `json:"operations"`
	Findings      []Finding    `json:"findings"`
	Limitations   []Limitation `json:"limitations"`
	Errors        []ScanError  `json:"errors"`
}

type ScanMetadata struct {
	ScannerVersion string    `json:"scannerVersion"`
	PolicyVersion  string    `json:"policyVersion"`
	StartedAt      time.Time `json:"startedAt"`
	CompletedAt    time.Time `json:"completedAt"`
	Sandboxed      bool      `json:"sandboxed"`
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
	Path        string  `json:"path"`
	Kind        string  `json:"kind"`
	Mode        string  `json:"mode"`
	Size        int64   `json:"size"`
	SHA256      string  `json:"sha256,omitempty"`
	ContentType string  `json:"contentType,omitempty"`
	LinkTarget  string  `json:"linkTarget,omitempty"`
	Inspected   bool    `json:"inspected"`
	SkipReason  string  `json:"skipReason,omitempty"`
	Binary      *Binary `json:"binary,omitempty"`
}

type Binary struct {
	Format      string   `json:"format"`
	Class       string   `json:"class"`
	ByteOrder   string   `json:"byteOrder"`
	Machine     string   `json:"machine"`
	Type        string   `json:"type"`
	Interpreter string   `json:"interpreter,omitempty"`
	Libraries   []string `json:"libraries"`
	HasSymbols  bool     `json:"hasSymbols"`
}

type Operation struct {
	ID         string     `json:"id"`
	Category   string     `json:"category"`
	Scope      Scope      `json:"scope"`
	Command    string     `json:"command,omitempty"`
	Arguments  []string   `json:"arguments,omitempty"`
	Dynamic    bool       `json:"dynamic"`
	Confidence Confidence `json:"confidence"`
	Evidence   Evidence   `json:"evidence"`
}

type Finding struct {
	ID          string     `json:"id"`
	Claim       ClaimType  `json:"claim"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	Category    string     `json:"category"`
	Scope       Scope      `json:"scope"`
	Title       string     `json:"title"`
	Explanation string     `json:"explanation"`
	Evidence    []Evidence `json:"evidence"`
	Related     []string   `json:"relatedOperationIds,omitempty"`
	Provenance  string     `json:"provenance"`
}

type Evidence struct {
	Path      string `json:"path"`
	LineStart int    `json:"lineStart,omitempty"`
	LineEnd   int    `json:"lineEnd,omitempty"`
	Operation string `json:"operation,omitempty"`
	Excerpt   string `json:"excerpt,omitempty"`
}

type Limitation struct {
	Code        string `json:"code"`
	Description string `json:"description"`
	Path        string `json:"path,omitempty"`
}

type ScanError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Path    string `json:"path,omitempty"`
}
