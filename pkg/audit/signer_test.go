package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSigner_KeyGenerationAndPEMRoundtrip(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "krypton_keys_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	kp, err := GenerateKeyPair()
	require.NoError(t, err)
	require.NotNil(t, kp)
	assert.Len(t, kp.PublicKey, ed25519.PublicKeySize)
	assert.Len(t, kp.PrivateKey, ed25519.PrivateKeySize)
	assert.NotEmpty(t, KeyID(kp.PublicKey))

	privPath := filepath.Join(tmpDir, "krypton_audit.key")
	pubPath := filepath.Join(tmpDir, "krypton_audit.pub")

	err = SaveKeyPair(kp, privPath, pubPath)
	require.NoError(t, err)

	loadedPriv, err := LoadPrivateKey(privPath)
	require.NoError(t, err)
	assert.Equal(t, kp.PrivateKey, loadedPriv)

	loadedPub, err := LoadPublicKey(pubPath)
	require.NoError(t, err)
	assert.Equal(t, kp.PublicKey, loadedPub)
}

func TestSigner_SignAndVerifyRoot(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	rootHash := sha256.Sum256([]byte("sample-merkle-root-32bytes-hash"))
	treeSize := int64(42)

	checkpoint, err := SignRoot(kp.PrivateKey, rootHash, treeSize)
	require.NoError(t, err)
	require.NotNil(t, checkpoint)
	assert.Equal(t, treeSize, checkpoint.TreeSize)
	assert.Equal(t, KeyID(kp.PublicKey), checkpoint.KeyID)
	assert.NotEmpty(t, checkpoint.Signature)

	// Valid verification
	assert.True(t, VerifyRootSignature(kp.PublicKey, checkpoint))

	// Tampered root hash
	tampered := *checkpoint
	tampered.RootHash = "0000000000000000000000000000000000000000000000000000000000000000"
	assert.False(t, VerifyRootSignature(kp.PublicKey, &tampered))

	// Tampered tree size
	tamperedSize := *checkpoint
	tamperedSize.TreeSize = 999
	assert.False(t, VerifyRootSignature(kp.PublicKey, &tamperedSize))

	// Different public key
	otherKP, _ := GenerateKeyPair()
	assert.False(t, VerifyRootSignature(otherKP.PublicKey, checkpoint))
}
