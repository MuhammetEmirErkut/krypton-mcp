package masker

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
)

var (
	// ErrTokenNotFound is returned when attempting to detokenize an unknown surrogate token
	ErrTokenNotFound = errors.New("surrogate token not found in vault")
	// ErrDecryptionFailed is returned when ciphertext authentication fails
	ErrDecryptionFailed = errors.New("failed to decrypt sensitive value from vault")
)

// Vault stores encrypted sensitive values associated with surrogate tokens in memory
type Vault struct {
	mu           sync.RWMutex
	aesKey       []byte                      // 32 bytes (256-bit) AES key
	hmacKey      []byte                      // 32 bytes HMAC key for deterministic token generation
	gcm          cipher.AEAD                 // AES-256-GCM cipher
	tokenToValue map[string][]byte           // surrogateToken -> encrypted ciphertext (nonce + ciphertext + tag)
	valueToToken map[string]string           // cleartext -> surrogateToken (for fast session caching)
}

// NewVault initializes a new in-memory cryptographic vault with freshly generated ephemeral keys
func NewVault() (*Vault, error) {
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return nil, fmt.Errorf("failed to generate secure AES key: %w", err)
	}

	hmacKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, hmacKey); err != nil {
		return nil, fmt.Errorf("failed to generate secure HMAC key: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GCM mode: %w", err)
	}

	return &Vault{
		aesKey:       aesKey,
		hmacKey:      hmacKey,
		gcm:          gcm,
		tokenToValue: make(map[string][]byte),
		valueToToken: make(map[string]string),
	}, nil
}

// Put securely encrypts and stores a cleartext value, returning its deterministic surrogate token
func (v *Vault) Put(ruleName string, cleartext string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Check if this cleartext has already been tokenized in this vault session
	if existingToken, exists := v.valueToToken[cleartext]; exists {
		return existingToken, nil
	}

	// Generate deterministic token suffix using HMAC-SHA256
	h := hmac.New(sha256.New, v.hmacKey)
	h.Write([]byte(cleartext))
	tokenHash := hex.EncodeToString(h.Sum(nil))[:8]

	rulePrefix := stringsCleanPrefix(ruleName)
	token := fmt.Sprintf("[%s_REF_%s]", rulePrefix, tokenHash)

	// Encrypt cleartext using AES-256-GCM
	nonce := make([]byte, v.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate GCM nonce: %w", err)
	}

	ciphertext := v.gcm.Seal(nonce, nonce, []byte(cleartext), []byte(token))

	v.tokenToValue[token] = ciphertext
	v.valueToToken[cleartext] = token

	return token, nil
}

// Get retrieves and decrypts the original cleartext value for a surrogate token
func (v *Vault) Get(token string) (string, error) {
	v.mu.RLock()
	ciphertext, exists := v.tokenToValue[token]
	v.mu.RUnlock()

	if !exists {
		return "", ErrTokenNotFound
	}

	nonceSize := v.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", ErrDecryptionFailed
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := v.gcm.Open(nil, nonce, actualCiphertext, []byte(token))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return string(plaintext), nil
}

// Size returns the count of unique tokenized values in the vault
func (v *Vault) Size() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.tokenToValue)
}

// Clear wipes all stored keys and encrypted records from memory
func (v *Vault) Clear() {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Zeroize memory buffers
	for i := range v.aesKey {
		v.aesKey[i] = 0
	}
	for i := range v.hmacKey {
		v.hmacKey[i] = 0
	}

	for k, val := range v.tokenToValue {
		for i := range val {
			val[i] = 0
		}
		delete(v.tokenToValue, k)
	}

	for k := range v.valueToToken {
		delete(v.valueToToken, k)
	}
}

func stringsCleanPrefix(ruleName string) string {
	if ruleName == "" {
		return "PII"
	}
	var res []byte
	for i := 0; i < len(ruleName); i++ {
		ch := ruleName[i]
		if (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			res = append(res, ch)
		} else if ch >= 'a' && ch <= 'z' {
			res = append(res, ch-32) // uppercase
		} else {
			res = append(res, '_')
		}
	}
	return string(res)
}
