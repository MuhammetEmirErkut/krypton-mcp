package audit

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMerkleTree_Empty(t *testing.T) {
	tree := NewMerkleTree()
	assert.Equal(t, int64(0), tree.LeafCount())
	assert.Equal(t, [32]byte{}, tree.CurrentRoot())

	_, err := tree.GenerateProof(0)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEmptyTree)
}

func TestMerkleTree_SingleLeaf(t *testing.T) {
	tree := NewMerkleTree()
	idx, leaf, root := tree.Append([]byte("initial audit entry"))

	assert.Equal(t, int64(0), idx)
	assert.Equal(t, leaf, root, "For a 1-leaf tree, root must equal the leaf hash")
	assert.Equal(t, int64(1), tree.LeafCount())

	proof, err := tree.GenerateProof(0)
	require.NoError(t, err)
	require.NotNil(t, proof)
	assert.Empty(t, proof.AuditPath)
	assert.True(t, VerifyProof(proof))
}

func TestMerkleTree_MultipleLeaves_BalancedAndUnbalanced(t *testing.T) {
	testSizes := []int{2, 3, 4, 5, 7, 8, 15, 16, 31, 32, 64, 100}

	for _, size := range testSizes {
		t.Run(fmt.Sprintf("Leaves_%d", size), func(t *testing.T) {
			tree := NewMerkleTree()

			for i := 0; i < size; i++ {
				tree.Append([]byte(fmt.Sprintf("event-payload-data-%d", i)))
			}

			assert.Equal(t, int64(size), tree.LeafCount())
			assert.NotEmpty(t, tree.CurrentRootHex())

			// Verify that every single leaf produces a valid cryptographic inclusion proof
			for i := 0; i < size; i++ {
				proof, err := tree.GenerateProof(int64(i))
				require.NoError(t, err, "Failed generating proof for leaf %d in tree size %d", i, size)
				require.True(t, VerifyProof(proof), "Proof verification failed for leaf %d in tree size %d", i, size)
			}
		})
	}
}

func TestMerkleTree_ProofTamperingDetection(t *testing.T) {
	tree := NewMerkleTree()
	for i := 0; i < 8; i++ {
		tree.Append([]byte(fmt.Sprintf("entry-%d", i)))
	}

	proof, err := tree.GenerateProof(3)
	require.NoError(t, err)
	require.True(t, VerifyProof(proof))

	// 1. Tamper with leaf hash
	tamperedProof := *proof
	tamperedProof.LeafHash = "0000000000000000000000000000000000000000000000000000000000000000"
	assert.False(t, VerifyProof(&tamperedProof), "Tampered leaf hash must fail verification")

	// 2. Tamper with sibling audit path
	tamperedPathProof := *proof
	tamperedPathProof.AuditPath = make([]string, len(proof.AuditPath))
	copy(tamperedPathProof.AuditPath, proof.AuditPath)
	tamperedPathProof.AuditPath[0] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	assert.False(t, VerifyProof(&tamperedPathProof), "Tampered sibling hash must fail verification")

	// 3. Tamper with root hash
	tamperedRootProof := *proof
	tamperedRootProof.RootHash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	assert.False(t, VerifyProof(&tamperedRootProof), "Tampered root hash must fail verification")
}

func TestMerkleTree_ConcurrentAppends(t *testing.T) {
	tree := NewMerkleTree()
	var wg sync.WaitGroup
	numWorkers := 30

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		workerID := i
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				tree.Append([]byte(fmt.Sprintf("worker-%d-msg-%d", workerID, j)))
			}
		}()
	}

	wg.Wait()
	assert.Equal(t, int64(numWorkers*20), tree.LeafCount())
	assert.NotEmpty(t, tree.CurrentRootHex())
}

func BenchmarkMerkleTree_Append(b *testing.B) {
	tree := NewMerkleTree()
	payload := []byte("benchmark-audit-event-log-payload-stream")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		tree.Append(payload)
	}
}
