package masker

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVault_EncryptAndDecryptRoundTrip(t *testing.T) {
	vault, err := NewVault()
	require.NoError(t, err)
	require.NotNil(t, vault)

	originalEmail := "sarah.connor@cyberdyne.com"
	token, err := vault.Put("email", originalEmail)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Contains(t, token, "[EMAIL_REF_")

	// Decrypt
	decrypted, err := vault.Get(token)
	require.NoError(t, err)
	assert.Equal(t, originalEmail, decrypted)
}

func TestVault_DeterministicTokens(t *testing.T) {
	vault, err := NewVault()
	require.NoError(t, err)

	card := "4532-0150-1234-5671"

	// Calling Put multiple times with identical cleartext must yield identical tokens
	token1, err := vault.Put("credit_card", card)
	require.NoError(t, err)

	token2, err := vault.Put("credit_card", card)
	require.NoError(t, err)

	assert.Equal(t, token1, token2, "Identical cleartext must produce deterministic token")
	assert.Equal(t, 1, vault.Size(), "Vault size should only count unique cleartext values")

	// Different cleartext must produce different tokens
	token3, err := vault.Put("credit_card", "5425-2334-3010-9903")
	require.NoError(t, err)
	assert.NotEqual(t, token1, token3)
	assert.Equal(t, 2, vault.Size())
}

func TestVault_ErrorsAndTampering(t *testing.T) {
	vault, err := NewVault()
	require.NoError(t, err)

	// Non-existent token
	_, err = vault.Get("[EMAIL_REF_ffffffff]")
	assert.ErrorIs(t, err, ErrTokenNotFound)

	// Tampered ciphertext
	token, err := vault.Put("api_key", "sk-1234567890abcdef1234567890abcdef")
	require.NoError(t, err)

	// Corrupt ciphertext in internal storage
	vault.mu.Lock()
	vault.tokenToValue[token][len(vault.tokenToValue[token])-1] ^= 0xFF
	vault.mu.Unlock()

	_, err = vault.Get(token)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestVault_Clear(t *testing.T) {
	vault, err := NewVault()
	require.NoError(t, err)

	token, err := vault.Put("email", "admin@krypton.io")
	require.NoError(t, err)
	assert.Equal(t, 1, vault.Size())

	vault.Clear()
	assert.Equal(t, 0, vault.Size())

	_, err = vault.Get(token)
	assert.ErrorIs(t, err, ErrTokenNotFound)
}

func TestVault_ConcurrentAccess(t *testing.T) {
	vault, err := NewVault()
	require.NoError(t, err)

	var wg sync.WaitGroup
	numWorkers := 30

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			email := fmt.Sprintf("user%d@enterprise.com", workerID%5)
			token, err := vault.Put("email", email)
			if assert.NoError(t, err) {
				val, err := vault.Get(token)
				assert.NoError(t, err)
				assert.Equal(t, email, val)
			}
		}(i)
	}

	wg.Wait()
	assert.Equal(t, 5, vault.Size())
}
