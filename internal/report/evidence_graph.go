package report

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
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
	Basis    ComparisonBasis
}

type digestFunction func([]byte) [32]byte

// BuildEvidenceGraph assigns stable public references and replaces the typed
// relationship collection atomically. Internal IDs remain the machine-facing
// identities used by deterministic analyzers.
func (r *Report) BuildEvidenceGraph() error {
	return r.buildEvidenceGraphWithDigest(sha256.Sum256)
}

func (r *Report) buildEvidenceGraphWithDigest(digest digestFunction) error {
	if r == nil {
		return errors.New("cannot build evidence graph for nil report")
	}
	r.bindEvidenceInputs()
	operationReferences := make(map[string]string, len(r.Operations))
	publicIdentities := make(map[string]string)
	assign := func(kind NodeKind, id string) (string, error) {
		reference := publicReferenceWithDigest(kind, id, digest)
		identity := string(kind) + "\x00" + id
		if previous, exists := publicIdentities[reference]; exists && previous != identity {
			return "", fmt.Errorf("public reference collision between %q and %q", previous, identity)
		}
		publicIdentities[reference] = identity
		return reference, nil
	}
	for index := range r.Operations {
		operation := &r.Operations[index]
		var err error
		operation.Reference, err = assign(NodeOperation, operation.ID)
		if err != nil {
			return err
		}
		operationReferences[operation.ID] = operation.Reference
	}
	for index := range r.Resources {
		resource := &r.Resources[index]
		var err error
		resource.Reference, err = assign(NodeResource, resource.ID)
		if err != nil {
			return err
		}
	}
	for index := range r.Findings {
		finding := &r.Findings[index]
		var err error
		finding.Reference, err = assign(NodeFinding, finding.ID)
		if err != nil {
			return err
		}
	}
	for index := range r.Unknowns {
		unknown := &r.Unknowns[index]
		var err error
		unknown.Reference, err = assign(NodeUnknown, unknown.ID)
		if err != nil {
			return err
		}
	}

	relationships := make([]Relationship, 0, len(r.Resources)+len(r.Findings)*2)
	relationshipIdentities := make(map[string]string)
	appendRelationship := func(kind RelationshipType, fromKind NodeKind, from, to string) error {
		if len(relationships) >= MaxProducedEvidenceRelations {
			return errors.New("evidence relationship production limit exceeded")
		}
		identity := string(kind) + "\x00" + string(fromKind) + "\x00" + from + "\x00" + string(NodeOperation) + "\x00" + to
		id := relationshipIDWithDigest(kind, fromKind, from, NodeOperation, to, digest)
		if previous, exists := relationshipIdentities[id]; exists && previous != identity {
			return fmt.Errorf("relationship ID collision")
		}
		relationshipIdentities[id] = identity
		relationships = append(relationships, Relationship{
			ID:       id,
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
	return nil
}

func (r *Report) bindEvidenceInputs() {
	external := ""
	for _, input := range r.EvidenceInputs {
		if input.Type == EvidenceInputOmarchyAudit && (external == "" || input.ID < external) {
			external = input.ID
		}
	}
	bind := func(value *Evidence, provenance Provenance) {
		if value.InputID != "" {
			return
		}
		value.InputID = TargetEvidenceInputID
		if provenance.EvidenceSource == EvidenceSourceOmarchyAudit {
			value.InputID = external
		}
	}
	for index := range r.Operations {
		bind(&r.Operations[index].Evidence, r.Operations[index].Provenance)
	}
	for index := range r.Resources {
		bind(&r.Resources[index].Evidence, r.Resources[index].Provenance)
	}
	for index := range r.Findings {
		for evidence := range r.Findings[index].Evidence {
			bind(&r.Findings[index].Evidence[evidence], r.Findings[index].Provenance)
		}
	}
	for index := range r.Unknowns {
		for evidence := range r.Unknowns[index].Evidence {
			bind(&r.Unknowns[index].Evidence[evidence], r.Unknowns[index].Provenance)
		}
		for origin := range r.Unknowns[index].Origins {
			bind(&r.Unknowns[index].Origins[origin].Evidence, r.Unknowns[index].Provenance)
		}
	}
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
	fromSubject, fromOK := r.semanticSubject(value.FromKind, value.FromID)
	toSubject, toOK := r.semanticSubject(value.ToKind, value.ToID)
	basis := value.Basis
	switch value.Type {
	case RelationshipCorroborates:
		if !fromOK || !toOK || fromSubject != toSubject || value.FromKind != value.ToKind || (value.FromKind != NodeOperation && value.FromKind != NodeResource) {
			return errors.New("corroboration requires compatible observations with the same semantic subject")
		}
		basis = ComparisonBasis{Kind: string(value.FromKind), Subject: fromSubject}
	case RelationshipDuplicates:
		if !fromOK || !toOK || fromSubject != toSubject || value.FromKind != value.ToKind || !r.duplicateEquivalent(value.FromKind, value.FromID, value.ToID) {
			return errors.New("duplication requires equivalent observations of the same kind")
		}
		basis = ComparisonBasis{Kind: string(value.FromKind), Subject: fromSubject}
	case RelationshipDisagreesWith:
		if basis.Kind != "coverage" || basis.Subject == "" || !fromOK || fromSubject != basis.Subject || value.ToKind != NodeFinding || !r.isCoverageDifferenceFinding(value.ToID) {
			return errors.New("disagreement requires an observation and a typed coverage-difference basis")
		}
	}
	fromKind, toKind := value.FromKind, value.ToKind
	if value.Type != RelationshipDisagreesWith && from > to {
		from, to, fromKind, toKind = to, from, toKind, fromKind
	}
	relationship := Relationship{Type: value.Type, FromKind: fromKind, From: from, ToKind: toKind, To: to, Comparison: &basis}
	relationship.ID = relationshipID(relationship.Type, relationship.FromKind, relationship.From, relationship.ToKind, relationship.To)
	for _, existing := range r.Relationships {
		if existing.ID == relationship.ID {
			return nil
		}
	}
	if len(r.Relationships) >= MaxProducedEvidenceRelations {
		return errors.New("evidence relationship production limit exceeded")
	}
	r.Relationships = append(r.Relationships, relationship)
	sort.Slice(r.Relationships, func(i, j int) bool { return r.Relationships[i].ID < r.Relationships[j].ID })
	return nil
}

func (r Report) duplicateEquivalent(kind NodeKind, firstID, secondID string) bool {
	switch kind {
	case NodeOperation:
		var first, second *Operation
		for index := range r.Operations {
			if r.Operations[index].ID == firstID {
				first = &r.Operations[index]
			}
			if r.Operations[index].ID == secondID {
				second = &r.Operations[index]
			}
		}
		return first != nil && second != nil && first.Category == second.Category && first.Scope == second.Scope && first.Command == second.Command && slices.Equal(first.Arguments, second.Arguments) && first.Dynamic == second.Dynamic && first.Confidence == second.Confidence
	case NodeResource:
		var first, second *Resource
		for index := range r.Resources {
			if r.Resources[index].ID == firstID {
				first = &r.Resources[index]
			}
			if r.Resources[index].ID == secondID {
				second = &r.Resources[index]
			}
		}
		return first != nil && second != nil && first.Kind == second.Kind && first.Access == second.Access && first.Value == second.Value && first.Sensitive == second.Sensitive && first.Dynamic == second.Dynamic && first.Scope == second.Scope && first.Confidence == second.Confidence
	}
	return false
}

func (r Report) semanticSubject(kind NodeKind, id string) (string, bool) {
	switch kind {
	case NodeOperation:
		for _, item := range r.Operations {
			if item.ID == id {
				return "command\x00" + filepath.Base(item.Command), true
			}
		}
	case NodeResource:
		for _, item := range r.Resources {
			if item.ID == id {
				return item.Kind + "\x00" + item.Access + "\x00" + item.Value, true
			}
		}
	}
	return "", false
}

func (r Report) isCoverageDifferenceFinding(id string) bool {
	for _, item := range r.Findings {
		if item.ID == id {
			return item.Category == "omarchy-audit-coverage-disagreement"
		}
	}
	return false
}

func publicReference(kind NodeKind, internalID string) string {
	return publicReferenceWithDigest(kind, internalID, sha256.Sum256)
}

func publicReferenceWithDigest(kind NodeKind, internalID string, digest digestFunction) string {
	sum := digest([]byte(string(kind) + "\x00" + internalID))
	return "PP-" + upperHex(sum[:16])
}

func relationshipID(kind RelationshipType, fromKind NodeKind, from string, toKind NodeKind, to string) string {
	return relationshipIDWithDigest(kind, fromKind, from, toKind, to, sha256.Sum256)
}

func relationshipIDWithDigest(kind RelationshipType, fromKind NodeKind, from string, toKind NodeKind, to string, digest digestFunction) string {
	sum := digest([]byte(string(kind) + "\x00" + string(fromKind) + "\x00" + from + "\x00" + string(toKind) + "\x00" + to))
	return "PE-" + upperHex(sum[:16])
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
