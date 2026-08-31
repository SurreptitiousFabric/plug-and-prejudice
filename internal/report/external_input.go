package report

import (
	"crypto/sha256"
	"encoding/hex"
)

// NewOmarchyAuditEvidenceInput binds an evidence-input declaration to the
// exact pinned document bytes that a trusted importer parses. The document
// digest says nothing about which target snapshot the document describes.
func NewOmarchyAuditEvidenceInput(id, label string, document []byte) EvidenceInput {
	digest := sha256.Sum256(document)
	return EvidenceInput{
		ID:             id,
		Type:           EvidenceInputOmarchyAudit,
		Label:          label,
		DocumentSHA256: hex.EncodeToString(digest[:]),
		Format:         OmarchyAuditInputFormat,
		Version:        OmarchyAuditInputVersion,
	}
}
