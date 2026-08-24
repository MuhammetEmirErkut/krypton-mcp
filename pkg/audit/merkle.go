package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrEmptyTree     = errors.New("merkle tree is empty")
	ErrIndexNotFound = errors.New("leaf index out of bounds")
	ErrInvalidProof  = errors.New("merkle proof verification failed")
)

const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// HashLeaf computes RFC 6962 leaf hash: SHA256(0x00 || data)
func HashLeaf(data []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(data)
	var res [32]byte
	copy(res[:], h.Sum(nil))
	return res
}

// HashNode computes RFC 6962 interior node hash: SHA256(0x01 || left || right)
func HashNode(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{nodePrefix})
	h.Write(left[:])
	h.Write(right[:])
	var res [32]byte
	copy(res[:], h.Sum(nil))
	return res
}

// MerkleTree is a thread-safe, high-performance append-only Merkle tree
type MerkleTree struct {
	mu     sync.RWMutex
	leaves [][32]byte
	root   [32]byte
}

// NewMerkleTree creates an empty MerkleTree
func NewMerkleTree() *MerkleTree {
	return &MerkleTree{
		leaves: make([][32]byte, 0),
	}
}

// LeafCount returns the number of leaves in the tree
func (t *MerkleTree) LeafCount() int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return int64(len(t.leaves))
}

// CurrentRoot returns the current root hash of the tree
func (t *MerkleTree) CurrentRoot() [32]byte {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.root
}

// CurrentRootHex returns the current root hash as a hex-encoded string
func (t *MerkleTree) CurrentRootHex() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return hex.EncodeToString(t.root[:])
}

// Append adds raw data bytes as a new leaf and recalculates the root
func (t *MerkleTree) Append(data []byte) (index int64, leafHash [32]byte, rootHash [32]byte) {
	leaf := HashLeaf(data)
	return t.AppendLeafHash(leaf)
}

// AppendLeafHash appends a precomputed leaf hash and updates the root
func (t *MerkleTree) AppendLeafHash(leaf [32]byte) (index int64, leafHash [32]byte, rootHash [32]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()

	idx := int64(len(t.leaves))
	t.leaves = append(t.leaves, leaf)
	t.root = t.computeRoot(t.leaves)

	return idx, leaf, t.root
}

// AppendEvent appends an AuditEvent to the tree and populates its LeafHash and MerkleRoot fields
func (t *MerkleTree) AppendEvent(evt *AuditEvent) (int64, [32]byte, error) {
	if evt == nil {
		return 0, [32]byte{}, errors.New("cannot append nil audit event")
	}

	digest := evt.Digest()
	leaf := HashLeaf(digest[:])

	idx, _, root := t.AppendLeafHash(leaf)

	evt.Index = idx
	evt.LeafHash = hex.EncodeToString(leaf[:])
	evt.MerkleRoot = hex.EncodeToString(root[:])

	return idx, root, nil
}

// computeRoot recursively computes the root hash of a slice of hashes
func (t *MerkleTree) computeRoot(hashes [][32]byte) [32]byte {
	n := len(hashes)
	if n == 0 {
		return [32]byte{}
	}
	if n == 1 {
		return hashes[0]
	}

	var nextLevel [][32]byte
	for i := 0; i < n; i += 2 {
		if i+1 < n {
			nextLevel = append(nextLevel, HashNode(hashes[i], hashes[i+1]))
		} else {
			// Odd element promoted to next level
			nextLevel = append(nextLevel, hashes[i])
		}
	}

	return t.computeRoot(nextLevel)
}

// GenerateProof creates a cryptographic audit path for the leaf at index
func (t *MerkleTree) GenerateProof(index int64) (*MerkleProof, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	totalLeaves := int64(len(t.leaves))
	if totalLeaves == 0 {
		return nil, ErrEmptyTree
	}
	if index < 0 || index >= totalLeaves {
		return nil, fmt.Errorf("%w: %d (total: %d)", ErrIndexNotFound, index, totalLeaves)
	}

	leafHash := t.leaves[index]
	var auditPath []string
	var directions []bool

	currentLevel := make([][32]byte, len(t.leaves))
	copy(currentLevel, t.leaves)
	currentIndex := int(index)

	for len(currentLevel) > 1 {
		var nextLevel [][32]byte
		levelLen := len(currentLevel)

		for i := 0; i < levelLen; i += 2 {
			if i+1 < levelLen {
				parent := HashNode(currentLevel[i], currentLevel[i+1])
				nextLevel = append(nextLevel, parent)

				// If current leaf/node is part of this pair, record its sibling
				if i == currentIndex {
					auditPath = append(auditPath, hex.EncodeToString(currentLevel[i+1][:]))
					directions = append(directions, true) // Sibling is on the right
				} else if i+1 == currentIndex {
					auditPath = append(auditPath, hex.EncodeToString(currentLevel[i][:]))
					directions = append(directions, false) // Sibling is on the left
				}
			} else {
				// Odd node promoted directly
				nextLevel = append(nextLevel, currentLevel[i])
			}
		}

		currentIndex = currentIndex / 2
		currentLevel = nextLevel
	}

	return &MerkleProof{
		LeafIndex:      index,
		LeafHash:       hex.EncodeToString(leafHash[:]),
		AuditPath:      auditPath,
		PathDirections: directions,
		RootHash:       hex.EncodeToString(t.root[:]),
		TreeSize:       totalLeaves,
	}, nil
}

// VerifyProof cryptographically validates that a leaf belongs to the tree represented by proof.RootHash
func VerifyProof(proof *MerkleProof) bool {
	if proof == nil || proof.LeafHash == "" || proof.RootHash == "" {
		return false
	}

	currentBytes, err := hex.DecodeString(proof.LeafHash)
	if err != nil || len(currentBytes) != 32 {
		return false
	}
	var current [32]byte
	copy(current[:], currentBytes)

	if len(proof.AuditPath) != len(proof.PathDirections) {
		return false
	}

	for i, siblingHex := range proof.AuditPath {
		siblingBytes, err := hex.DecodeString(siblingHex)
		if err != nil || len(siblingBytes) != 32 {
			return false
		}
		var sibling [32]byte
		copy(sibling[:], siblingBytes)

		isRightSibling := proof.PathDirections[i]
		if isRightSibling {
			current = HashNode(current, sibling)
		} else {
			current = HashNode(sibling, current)
		}
	}

	expectedRootBytes, err := hex.DecodeString(proof.RootHash)
	if err != nil || len(expectedRootBytes) != 32 {
		return false
	}

	var expectedRoot [32]byte
	copy(expectedRoot[:], expectedRootBytes)

	return current == expectedRoot
}
