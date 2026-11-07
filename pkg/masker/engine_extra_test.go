package masker

import (
	"testing"

	"github.com/krypton-mcp/krypton/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIBANValidation(t *testing.T) {
	assert.True(t, ValidateIBAN("GB82 WEST 1234 5698 7654 32"))
	assert.True(t, ValidateIBAN("DE89370400440532013000"))
	assert.False(t, ValidateIBAN("GB82 WEST 1234 5698 7654 33"))
	assert.False(t, ValidateIBAN("XX00"))
}

func TestEngineNewRules(t *testing.T) {
	e, err := NewRuleEngine(&config.MaskingConfig{BuiltinRules: []string{"iban", "api_key"}})
	require.NoError(t, err)
	in := "pay GB82 WEST 1234 5698 7654 32 key sk_live_abcdefghijklmnop1234 slack xoxb-1234567890-abcdefghij bad GB82 WEST 1234 5698 7654 33"
	var names []string
	for _, m := range e.Scan(in) {
		names = append(names, m.RuleName)
	}
	assert.ElementsMatch(t, []string{"iban", "stripe_key", "slack_token"}, names)
}

func TestEngineRejectsUnknownBuiltinRule(t *testing.T) {
	_, err := NewRuleEngine(&config.MaskingConfig{BuiltinRules: []string{"emial"}})
	assert.Error(t, err)
}

func FuzzScan(f *testing.F) {
	e, _ := NewRuleEngine(&config.MaskingConfig{BuiltinRules: []string{"email", "credit_card", "ssn", "api_key", "jwt", "phone", "ip_address", "iban"}})
	f.Add("mail a@b.co card 4111 1111 1111 1111 ip 10.0.0.1")
	f.Fuzz(func(t *testing.T, s string) {
		prev := -1
		for _, m := range e.Scan(s) {
			if m.Start < prev || m.End > len(s) || m.Start >= m.End || s[m.Start:m.End] != m.Value {
				t.Fatalf("bad match %+v", m)
			}
			prev = m.End
		}
	})
}
