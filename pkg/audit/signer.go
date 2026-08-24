package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var (
	ErrInvalidSignature = errors.New("cryptographic signature verification failed")
	ErrInvalidKey       = errors.New("invalid Ed25519 key")
)

// KeyPair holds asymmetric Ed25519 public and private keys
type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// GenerateKeyPair generates a new high-entropy Ed25519 keypair
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 keypair: %w", err)
	}
	return &KeyPair{
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// KeyID computes the short hex-encoded fingerprint of a public key
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// SaveKeyPair writes private and public keys to PEM files on disk with restricted permissions
func SaveKeyPair(kp *KeyPair, privPath, pubPath string) error {
	if kp == nil || kp.PrivateKey == nil || kp.PublicKey == nil {
		return ErrInvalidKey
	}

	if err := os.MkdirAll(filepath.Dir(privPath), 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(pubPath), 0755); err != nil {
		return err
	}

	privBlock := &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: kp.PrivateKey,
	}
	if err := os.WriteFile(privPath, pem.EncodeToMemory(privBlock), 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	pubBlock := &pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: kp.PublicKey,
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(pubBlock), 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// LoadPrivateKey reads an Ed25519 private key from a PEM file
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || len(block.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key in %s", path)
	}

	return ed25519.PrivateKey(block.Bytes), nil
}

// LoadPublicKey reads an Ed25519 public key from a PEM file
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || len(block.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key in %s", path)
	}

	return ed25519.PublicKey(block.Bytes), nil
}

// SignedCheckpoint represents a cryptographically signed snapshot of the Merkle ledger
type SignedCheckpoint struct {
	TreeSize  int64     `json:"tree_size"`
	RootHash  string    `json:"root_hash"`
	Timestamp time.Time `json:"timestamp"`
	KeyID     string    `json:"key_id"`
	Signature string    `json:"signature"`
}

// SignRoot signs a 32-byte Merkle root hash using an Ed25519 private key
func SignRoot(privKey ed25519.PrivateKey, rootHash [32]byte, treeSize int64) (*SignedCheckpoint, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidKey
	}

	now := time.Now().UTC()
	pubKey := privKey.Public().(ed25519.PublicKey)

	// Canonical payload to sign: "krypton-merkle-checkpoint\n<treeSize>\n<rootHashHex>\n<RFC3339Timestamp>"
	rootHex := hex.EncodeToString(rootHash[:])
	msg := fmt.Sprintf("krypton-merkle-checkpoint\n%d\n%s\n%s", treeSize, rootHex, now.Format(time.RFC3339Nano))

	sig := ed25519.Sign(privKey, []byte(msg))

	return &SignedCheckpoint{
		TreeSize:  treeSize,
		RootHash:  rootHex,
		Timestamp: now,
		KeyID:     KeyID(pubKey),
		Signature: hex.EncodeToString(sig),
	}, nil
}

// VerifyRootSignature validates a SignedCheckpoint against an Ed25519 public key
func VerifyRootSignature(pubKey ed25519.PublicKey, checkpoint *SignedCheckpoint) bool {
	if len(pubKey) != ed25519.PublicKeySize || checkpoint == nil {
		return false
	}

	sigBytes, err := hex.DecodeString(checkpoint.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}

	msg := fmt.Sprintf("krypton-merkle-checkpoint\n%d\n%s\n%s",
		checkpoint.TreeSize, checkpoint.RootHash, checkpoint.Timestamp.Format(time.RFC3339Nano))

	return ed25519.Verify(pubKey, []byte(msg), sigBytes)
}
