package masker

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/krypton-mcp/krypton/internal/config"
)

var (
	// regexSurrogateToken identifies Krypton surrogate tokens for detokenization
	regexSurrogateToken = regexp.MustCompile(`\[[A-Z0-9_]+_REF_[a-f0-9]{8}\]`)
)

// Tokenizer orchestrates sensitive data masking, deterministic surrogate token generation, and unmasking
type Tokenizer struct {
	engine   *RuleEngine
	vault    *Vault
	mode     string
	hashSalt []byte
}

// NewTokenizer initializes a Tokenizer with rule engine and cryptographic vault
func NewTokenizer(cfg *config.MaskingConfig, vault *Vault) (*Tokenizer, error) {
	engine, err := NewRuleEngine(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize rule engine for tokenizer: %w", err)
	}

	if vault == nil {
		var err error
		vault, err = NewVault()
		if err != nil {
			return nil, fmt.Errorf("failed to create default vault: %w", err)
		}
	}

	mode := config.MaskModeTokenize
	if cfg != nil && cfg.Mode != "" {
		mode = cfg.Mode
	}

	salt := make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, salt)

	return &Tokenizer{
		engine:   engine,
		vault:    vault,
		mode:     mode,
		hashSalt: salt,
	}, nil
}

// Vault returns the underlying cryptographic token vault
func (t *Tokenizer) Vault() *Vault {
	return t.vault
}

// Engine returns the underlying rule engine
func (t *Tokenizer) Engine() *RuleEngine {
	return t.engine
}

// MaskText scans the input string and replaces sensitive spans based on the configured MaskMode
func (t *Tokenizer) MaskText(input string) (string, int, error) {
	if input == "" {
		return "", 0, nil
	}

	matches := t.engine.Scan(input)
	if len(matches) == 0 {
		return input, 0, nil
	}

	var builder strings.Builder
	builder.Grow(len(input))

	lastIdx := 0
	tokenCount := 0

	for _, m := range matches {
		builder.WriteString(input[lastIdx:m.Start])

		var replacement string
		switch t.mode {
		case config.MaskModeTokenize:
			token, err := t.vault.Put(m.RuleName, m.Value)
			if err != nil {
				return "", 0, fmt.Errorf("failed to store token in vault: %w", err)
			}
			replacement = token

		case config.MaskModeRedact:
			if m.Replacement != "" {
				replacement = m.Replacement
			} else {
				prefix := stringsCleanPrefix(m.RuleName)
				replacement = fmt.Sprintf("[REDACTED_%s]", prefix)
			}

		case config.MaskModeHash:
			h := hmac.New(sha256.New, t.hashSalt)
			h.Write([]byte(m.Value))
			hash := hex.EncodeToString(h.Sum(nil))[:8]
			prefix := stringsCleanPrefix(m.RuleName)
			replacement = fmt.Sprintf("[HASH_%s_%s]", prefix, hash)

		default:
			token, err := t.vault.Put(m.RuleName, m.Value)
			if err != nil {
				return "", 0, err
			}
			replacement = token
		}

		builder.WriteString(replacement)
		lastIdx = m.End
		tokenCount++
	}

	builder.WriteString(input[lastIdx:])
	return builder.String(), tokenCount, nil
}

// UnmaskText reverses surrogate tokens within the text back to their decrypted cleartext values
func (t *Tokenizer) UnmaskText(input string) (string, error) {
	if input == "" || t.vault == nil || t.vault.Size() == 0 {
		return input, nil
	}

	var lastErr error

	unmasked := regexSurrogateToken.ReplaceAllStringFunc(input, func(token string) string {
		cleartext, err := t.vault.Get(token)
		if err != nil {
			// If token was not found in vault (or corrupted), keep original token unchanged
			lastErr = err
			return token
		}
		return cleartext
	})

	// If no tokens were present, return input
	if lastErr != nil && lastErr != ErrTokenNotFound {
		return unmasked, lastErr
	}

	return unmasked, nil
}
