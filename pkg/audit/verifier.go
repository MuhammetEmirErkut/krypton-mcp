package audit

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// VerificationReport contains detailed diagnostics on ledger integrity
type VerificationReport struct {
	TotalEvents    int64    `json:"total_events"`
	Valid          bool     `json:"valid"`
	ComputedRoot   string   `json:"computed_root"`
	ExpectedRoot   string   `json:"expected_root"`
	SignatureValid *bool    `json:"signature_valid,omitempty"`
	Errors         []string `json:"errors,omitempty"`
}

// VerifyLogFile streams and verifies every line of an audit.jsonl log file, recomputing the Merkle Tree
func VerifyLogFile(logPath string, pubKey ed25519.PublicKey) (*VerificationReport, error) {
	file, err := os.Open(logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file '%s': %w", logPath, err)
	}
	defer file.Close()

	tree := NewMerkleTree()
	report := &VerificationReport{
		Valid:  true,
		Errors: make([]string, 0),
	}

	scanner := bufio.NewScanner(file)
	// Allow large scan buffers for big payloads
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	var lastRecordedRoot string
	var lineNum int64

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var evt AuditEvent
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			report.Valid = false
			report.Errors = append(report.Errors, fmt.Sprintf("line %d: invalid JSON format: %v", lineNum+1, err))
			lineNum++
			continue
		}

		// 1. Verify index sequence
		if evt.Index != lineNum {
			report.Valid = false
			report.Errors = append(report.Errors, fmt.Sprintf("line %d: non-sequential index (expected %d, got %d)", lineNum+1, lineNum, evt.Index))
		}

		// 2. Recompute canonical digest & leaf hash
		digest := evt.Digest()
		expectedLeaf := HashLeaf(digest[:])
		expectedLeafHex := hex.EncodeToString(expectedLeaf[:])

		if evt.LeafHash != expectedLeafHex {
			report.Valid = false
			report.Errors = append(report.Errors, fmt.Sprintf("event %s (idx %d): leaf hash mismatch (recorded: %s, recomputed: %s)", evt.ID, evt.Index, evt.LeafHash, expectedLeafHex))
		}

		// 3. Append to reconstructed tree and verify intermediate Merkle root
		_, _, root := tree.AppendLeafHash(expectedLeaf)
		computedRootHex := hex.EncodeToString(root[:])

		if evt.MerkleRoot != computedRootHex {
			report.Valid = false
			report.Errors = append(report.Errors, fmt.Sprintf("event %s (idx %d): merkle root mismatch (recorded: %s, computed: %s)", evt.ID, evt.Index, evt.MerkleRoot, computedRootHex))
		}

		lastRecordedRoot = evt.MerkleRoot
		lineNum++
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading audit log: %w", err)
	}

	report.TotalEvents = lineNum
	report.ComputedRoot = tree.CurrentRootHex()
	report.ExpectedRoot = lastRecordedRoot

	if lineNum == 0 {
		report.Valid = true
		report.ComputedRoot = hex.EncodeToString(make([]byte, 32))
		return report, nil
	}

	if report.ComputedRoot != report.ExpectedRoot {
		report.Valid = false
		report.Errors = append(report.Errors, fmt.Sprintf("final computed root '%s' does not match last recorded root '%s'", report.ComputedRoot, report.ExpectedRoot))
	}

	return report, nil
}

// ExportProofFromLog rebuilds the Merkle tree from a log file and generates a cryptographic proof for a specific leaf
func ExportProofFromLog(logPath string, targetIndex int64) (*MerkleProof, error) {
	file, err := os.Open(logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}
	defer file.Close()

	tree := NewMerkleTree()
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var evt AuditEvent
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			return nil, fmt.Errorf("invalid audit entry JSON: %w", err)
		}

		digest := evt.Digest()
		leaf := HashLeaf(digest[:])
		tree.AppendLeafHash(leaf)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return tree.GenerateProof(targetIndex)
}
