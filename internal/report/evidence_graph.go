package report

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

// Comparison identifies two already-retained nodes by their internal IDs.
// It is an in-memory construction request, not part of the serialized schema.
type Comparison struct {
	Type     RelationshipType
	FromKind NodeKind
	FromID   string
	ToKind   NodeKind
	ToID     string
}

// BuildEvidenceGraph assigns stable public references and replaces the typed
// relationship collection atomically. Internal IDs remain the machine-facing
// identities used by deterministic analyzers.
func (r *Report) BuildEvidenceGraph() error {
	if r == nil {
		return errors.New("cannot build evidence graph for nil report")
	}
	operationReferences := make(map[string]string, len(r.Operations))
	for index := range r.Operations {
		operation := &r.Operations[index]
		operation.Reference = publicReference(NodeOperation, operation.ID)
		operationReferences[operation.ID] = operation.Reference
	}
	for index := range r.Resources {
		resource := &r.Resources[index]
		resource.Reference = publicReference(NodeResource, resource.ID)
	}
	for index := range r.Findings {
		finding := &r.Findings[index]
		finding.Reference = publicReference(NodeFinding, finding.ID)
	}
	for index := range r.Unknowns {
		unknown := &r.Unknowns[index]
		unknown.Reference = publicReference(NodeUnknown, unknown.ID)
	}

	relationships := make([]Relationship, 0, len(r.Resources)+len(r.Findings)*2)
	appendRelationship := func(kind RelationshipType, fromKind NodeKind, from, to string) error {
		if len(relationships) >= MaxEvidenceRelations {
			return errors.New("evidence relationship production limit exceeded")
		}
		relationships = append(relationships, Relationship{
			ID:       relationshipID(kind, fromKind, from, NodeOperation, to),
			Type:     kind,
			FromKind: fromKind,
			From:     from,
			ToKind:   NodeOperation,
			To:       to,
		})
		return nil
	}
	for _, resource := range r.Resources {
		if err := appendRelationship(RelationshipDerivedFrom, NodeResource, resource.Reference, operationReferences[resource.RelatedOperationID]); err != nil {
			return err
		}
	}
	for _, finding := range r.Findings {
		relationshipType := RelationshipEstablishedBy
		switch finding.Claim {
		case ClaimInference:
			relationshipType = RelationshipInferredFrom
		case ClaimUnknown:
			relationshipType = RelationshipUnknownBecause
		}
		for _, related := range finding.Related {
			if err := appendRelationship(relationshipType, NodeFinding, finding.Reference, operationReferences[related]); err != nil {
				return err
			}
		}
	}
	for _, unknown := range r.Unknowns {
		for _, affected := range unknown.AffectedOperations {
			if err := appendRelationship(RelationshipUnknownBecause, NodeUnknown, unknown.Reference, operationReferences[affected]); err != nil {
				return err
			}
		}
	}
	sort.Slice(relationships, func(i, j int) bool { return relationships[i].ID < relationships[j].ID })
	r.Relationships = relationships
	if r.Review != nil {
		return r.BuildReviewSummary(r.Review.AnalysisCoverage)
	}
	return nil
}

// AddComparison appends a canonical cross-observation relationship after the
// base evidence graph has assigned public references. Validate independently
// enforces source independence and rejects contradictory pairs.
func (r *Report) AddComparison(value Comparison) error {
	if value.Type != RelationshipCorroborates && value.Type != RelationshipDisagreesWith && value.Type != RelationshipDuplicates {
		return errors.New("comparison relationship type is invalid")
	}
	lookup := func(kind NodeKind, id string) (string, bool) {
		switch kind {
		case NodeOperation:
			for _, item := range r.Operations {
				if item.ID == id {
					return item.Reference, item.Reference != ""
				}
			}
		case NodeResource:
			for _, item := range r.Resources {
				if item.ID == id {
					return item.Reference, item.Reference != ""
				}
			}
		case NodeFinding:
			for _, item := range r.Findings {
				if item.ID == id {
					return item.Reference, item.Reference != ""
				}
			}
		case NodeUnknown:
			for _, item := range r.Unknowns {
				if item.ID == id {
					return item.Reference, item.Reference != ""
				}
			}
		}
		return "", false
	}
	from, ok := lookup(value.FromKind, value.FromID)
	if !ok {
		return fmt.Errorf("comparison source %s %q is missing", value.FromKind, value.FromID)
	}
	to, ok := lookup(value.ToKind, value.ToID)
	if !ok {
		return fmt.Errorf("comparison target %s %q is missing", value.ToKind, value.ToID)
	}
	fromKind, toKind := value.FromKind, value.ToKind
	if from > to {
		from, to, fromKind, toKind = to, from, toKind, fromKind
	}
	relationship := Relationship{Type: value.Type, FromKind: fromKind, From: from, ToKind: toKind, To: to}
	relationship.ID = relationshipID(relationship.Type, relationship.FromKind, relationship.From, relationship.ToKind, relationship.To)
	for _, existing := range r.Relationships {
		if existing.ID == relationship.ID {
			return nil
		}
	}
	if len(r.Relationships) >= MaxEvidenceRelations {
		return errors.New("evidence relationship production limit exceeded")
	}
	r.Relationships = append(r.Relationships, relationship)
	sort.Slice(r.Relationships, func(i, j int) bool { return r.Relationships[i].ID < r.Relationships[j].ID })
	return nil
}

func publicReference(kind NodeKind, internalID string) string {
	sum := sha256.Sum256([]byte(string(kind) + "\x00" + internalID))
	return "PP-" + upperHex(sum[:8])
}

func relationshipID(kind RelationshipType, fromKind NodeKind, from string, toKind NodeKind, to string) string {
	sum := sha256.Sum256([]byte(string(kind) + "\x00" + string(fromKind) + "\x00" + from + "\x00" + string(toKind) + "\x00" + to))
	return "PE-" + upperHex(sum[:8])
}

func upperHex(value []byte) string {
	encoded := make([]byte, hex.EncodedLen(len(value)))
	hex.Encode(encoded, value)
	for index := range encoded {
		if encoded[index] >= 'a' && encoded[index] <= 'f' {
			encoded[index] -= 'a' - 'A'
		}
	}
	return string(encoded)
}
