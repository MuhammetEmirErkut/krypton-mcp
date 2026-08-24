package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/krypton-mcp/krypton/pkg/credentials"
)

// EventType classifies the category of audited gateway activity
type EventType string

const (
	EventMCPRequest        EventType = "mcp_request"
	EventMCPResponse       EventType = "mcp_response"
	EventToolExecution     EventType = "tool_execution"
	EventCredentialLease   EventType = "credential_lease"
	EventSecurityViolation EventType = "security_violation"
)

// AuditEvent represents a tamper-evident record of gateway activity
type AuditEvent struct {
	Index       int64          `json:"index"`
	ID          string         `json:"id"`
	Timestamp   time.Time      `json:"timestamp"`
	Type        EventType      `json:"type"`
	SessionID   string         `json:"session_id,omitempty"`
	Actor       string         `json:"actor"` // "client", "server", "gateway"
	Method      string         `json:"method,omitempty"`
	PayloadHash string         `json:"payload_hash"`
	Data        map[string]any `json:"data,omitempty"`
	LeafHash    string         `json:"leaf_hash"`
	MerkleRoot  string         `json:"merkle_root"`
}

// ComputePayloadHash returns the hex-encoded SHA-256 digest of arbitrary payload bytes
func ComputePayloadHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// NewAuditEvent creates an initialized AuditEvent with a unique ID, timestamp, and payload hash
func NewAuditEvent(eventType EventType, actor, method string, rawPayload []byte, data map[string]any) *AuditEvent {
	now := time.Now().UTC()
	evtID := credentials.GenerateLeaseID("evt")

	payloadHash := ""
	if len(rawPayload) > 0 {
		payloadHash = ComputePayloadHash(rawPayload)
	}

	return &AuditEvent{
		ID:          evtID,
		Timestamp:   now,
		Type:        eventType,
		Actor:       actor,
		Method:      method,
		PayloadHash: payloadHash,
		Data:        data,
	}
}

// Digest generates a deterministic canonical SHA-256 byte hash of the event contents
func (e *AuditEvent) Digest() [32]byte {
	type canonicalEvent struct {
		ID          string         `json:"id"`
		Timestamp   string         `json:"timestamp"`
		Type        string         `json:"type"`
		Actor       string         `json:"actor"`
		Method      string         `json:"method,omitempty"`
		PayloadHash string         `json:"payload_hash"`
		Data        map[string]any `json:"data,omitempty"`
	}

	c := canonicalEvent{
		ID:          e.ID,
		Timestamp:   e.Timestamp.Format(time.RFC3339Nano),
		Type:        string(e.Type),
		Actor:       e.Actor,
		Method:      e.Method,
		PayloadHash: e.PayloadHash,
		Data:        e.Data,
	}

	bytes, _ := json.Marshal(c)
	return sha256.Sum256(bytes)
}

// MerkleProof contains the cryptographic path necessary to verify inclusion in a Merkle root
type MerkleProof struct {
	LeafIndex      int64      `json:"leaf_index"`
	LeafHash       string     `json:"leaf_hash"`
	AuditPath      []string   `json:"audit_path"`
	PathDirections []bool     `json:"path_directions"` // true if sibling is on the right, false if left
	RootHash       string     `json:"root_hash"`
	TreeSize       int64      `json:"tree_size"`
}

// String returns a human-readable summary of the proof
func (p *MerkleProof) String() string {
	return fmt.Sprintf("MerkleProof(Leaf: %d, PathLen: %d, Root: %s)", p.LeafIndex, len(p.AuditPath), p.RootHash)
}
