package masker

import (
	"testing"

	"github.com/krypton-mcp/krypton/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuleEngine_DefaultScan(t *testing.T) {
	engine, err := NewRuleEngine(nil)
	require.NoError(t, err)
	require.NotNil(t, engine)

	input := `
Hello, my contact email is john.doe@company.com and my direct line is 555-234-5678.
My backup server is located at 192.168.1.100.
Here is the client credit card: 4532-0150-1234-5671 and SSN is 123-45-6789.
AWS credentials: AKIAIOSFODNN7EXAMPLE and OpenAI: sk-abcdefghijklmnopqrstuvwxyz123456
`

	matches := engine.Scan(input)
	require.NotEmpty(t, matches)

	detectedTypes := make(map[string]bool)
	for _, m := range matches {
		detectedTypes[string(m.RuleType)] = true
	}

	assert.True(t, detectedTypes[string(RuleEmail)], "Should detect email")
	assert.True(t, detectedTypes[string(RulePhone)], "Should detect phone")
	assert.True(t, detectedTypes[string(RuleIPAddress)], "Should detect IP address")
	assert.True(t, detectedTypes[string(RuleCreditCard)], "Should detect credit card")
	assert.True(t, detectedTypes[string(RuleSSN)], "Should detect SSN")
	assert.True(t, detectedTypes[string(RuleAPIKey)], "Should detect API keys")

	assert.True(t, engine.ContainsSensitiveData(input))
	assert.False(t, engine.ContainsSensitiveData("Plain text without any sensitive tokens."))
}

func TestRuleEngine_CustomPatterns(t *testing.T) {
	cfg := &config.MaskingConfig{
		BuiltinRules: []string{"email"},
		CustomPatterns: []config.CustomPattern{
			{
				Name:        "employee_id",
				Pattern:     `EMP-\d{6}`,
				Replacement: "[EMP_ID]",
			},
		},
	}

	engine, err := NewRuleEngine(cfg)
	require.NoError(t, err)

	input := "Employee EMP-987654 sent an email to admin@corp.net"
	matches := engine.Scan(input)
	require.Len(t, matches, 2)

	assert.Equal(t, "employee_id", matches[0].RuleName)
	assert.Equal(t, "EMP-987654", matches[0].Value)
	assert.Equal(t, "[EMP_ID]", matches[0].Replacement)

	assert.Equal(t, "email", matches[1].RuleName)
	assert.Equal(t, "admin@corp.net", matches[1].Value)
}

func TestRuleEngine_InvalidCustomPattern(t *testing.T) {
	cfg := &config.MaskingConfig{
		CustomPatterns: []config.CustomPattern{
			{
				Name:    "broken_regex",
				Pattern: `[unclosed-bracket`,
			},
		},
	}

	engine, err := NewRuleEngine(cfg)
	require.Error(t, err)
	assert.Nil(t, engine)
}

func TestRuleEngine_OverlapResolution(t *testing.T) {
	engine, err := NewRuleEngine(nil)
	require.NoError(t, err)

	input := "Contact user192.168.1.1@domain.com for support"
	matches := engine.Scan(input)

	require.Len(t, matches, 1)
	assert.Equal(t, RuleEmail, matches[0].RuleType)
	assert.Equal(t, "user192.168.1.1@domain.com", matches[0].Value)
}

func BenchmarkRuleEngine_Scan(b *testing.B) {
	engine, err := NewRuleEngine(nil)
	if err != nil {
		b.Fatalf("failed to create engine: %v", err)
	}

	samplePayload := `
User query: "Retrieve account details for alice@example.com, card: 4532-0150-1234-5671, SSN: 123-45-6789.
Also check API endpoint https://10.0.0.1/api using token sk-abcdefghijklmnopqrstuvwxyz123456."
`
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = engine.Scan(samplePayload)
	}
}

func BenchmarkValidateCreditCard(b *testing.B) {
	card := "4532-0150-1234-5671"
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = ValidateCreditCard(card)
	}
}
