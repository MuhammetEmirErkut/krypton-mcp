package masker

import (
	"testing"

	"github.com/krypton-mcp/krypton/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenizer_MaskAndUnmaskRoundTrip(t *testing.T) {
	tokenizer, err := NewTokenizer(nil, nil)
	require.NoError(t, err)

	originalText := "Please invoice customer john.doe@company.com using credit card 4532-0150-1234-5671 and notify 555-123-4567."

	// 1. Mask
	maskedText, count, err := tokenizer.MaskText(originalText)
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	assert.NotContains(t, maskedText, "john.doe@company.com")
	assert.NotContains(t, maskedText, "4532-0150-1234-5671")
	assert.NotContains(t, maskedText, "555-123-4567")

	assert.Contains(t, maskedText, "[EMAIL_REF_")
	assert.Contains(t, maskedText, "[CREDIT_CARD_REF_")
	assert.Contains(t, maskedText, "[PHONE_REF_")

	// 2. Unmask
	restoredText, err := tokenizer.UnmaskText(maskedText)
	require.NoError(t, err)
	assert.Equal(t, originalText, restoredText)
}

func TestTokenizer_DeterministicTokenConsistency(t *testing.T) {
	tokenizer, err := NewTokenizer(nil, nil)
	require.NoError(t, err)

	// Repeating same email in multiple places
	text := "Email 1: alice@domain.com, Email 2: alice@domain.com, Email 3: bob@domain.com"
	masked, count, err := tokenizer.MaskText(text)
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	// Count unique surrogate tokens
	matches := regexSurrogateToken.FindAllString(masked, -1)
	require.Len(t, matches, 3)

	assert.Equal(t, matches[0], matches[1], "Identical emails must receive identical tokens")
	assert.NotEqual(t, matches[0], matches[2], "Distinct emails must receive distinct tokens")

	restored, err := tokenizer.UnmaskText(masked)
	require.NoError(t, err)
	assert.Equal(t, text, restored)
}

func TestTokenizer_MaskModeRedact(t *testing.T) {
	cfg := &config.MaskingConfig{
		Mode:         config.MaskModeRedact,
		BuiltinRules: []string{"email", "credit_card"},
		CustomPatterns: []config.CustomPattern{
			{
				Name:        "api_token",
				Pattern:     `SECRET-[A-Z0-9]{8}`,
				Replacement: "[CUSTOM_SECRET_REDACTED]",
			},
		},
	}

	tokenizer, err := NewTokenizer(cfg, nil)
	require.NoError(t, err)

	input := "Send SECRET-ABC12345 to admin@example.com with card 4532-0150-1234-5671"
	masked, count, err := tokenizer.MaskText(input)
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	assert.Contains(t, masked, "[CUSTOM_SECRET_REDACTED]")
	assert.Contains(t, masked, "[REDACTED_EMAIL]")
	assert.Contains(t, masked, "[REDACTED_CREDIT_CARD]")
}

func TestTokenizer_MaskModeHash(t *testing.T) {
	cfg := &config.MaskingConfig{
		Mode:         config.MaskModeHash,
		BuiltinRules: []string{"email"},
	}

	tokenizer, err := NewTokenizer(cfg, nil)
	require.NoError(t, err)

	input := "User contact: alice@corp.com"
	masked, count, err := tokenizer.MaskText(input)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	assert.Contains(t, masked, "[HASH_EMAIL_")
	assert.NotContains(t, masked, "alice@corp.com")
}

func TestTokenizer_UnmaskWithUnknownTokens(t *testing.T) {
	tokenizer, err := NewTokenizer(nil, nil)
	require.NoError(t, err)

	input := "Text with [UNKNOWN_REF_12345678] and no matching vault record"
	unmasked, err := tokenizer.UnmaskText(input)
	require.NoError(t, err)
	assert.Equal(t, input, unmasked, "Unknown tokens should remain intact")
}

func BenchmarkTokenizer_MaskText(b *testing.B) {
	tokenizer, _ := NewTokenizer(nil, nil)
	sample := "User alice@example.com purchased item with card 4532-0150-1234-5671 and SSN 123-45-6789."

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _, _ = tokenizer.MaskText(sample)
	}
}

func BenchmarkTokenizer_UnmaskText(b *testing.B) {
	tokenizer, _ := NewTokenizer(nil, nil)
	sample := "User alice@example.com purchased item with card 4532-0150-1234-5671."
	masked, _, _ := tokenizer.MaskText(sample)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = tokenizer.UnmaskText(masked)
	}
}
