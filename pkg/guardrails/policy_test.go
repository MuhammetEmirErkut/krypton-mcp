package guardrails

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyEngine_AllowAndDenylists(t *testing.T) {
	cfg := &PolicyConfig{
		AllowedTools:   []string{"query_*", "fetch_user"},
		ForbiddenTools: []string{"query_dangerous_admin", "drop_*"},
	}

	engine, err := NewPolicyEngine(cfg)
	require.NoError(t, err)

	// 1. Allowed tool
	allowed, _ := engine.EvaluateToolCall("fetch_user", nil)
	assert.True(t, allowed)

	allowed, _ = engine.EvaluateToolCall("query_orders", nil)
	assert.True(t, allowed)

	// 2. Explicitly forbidden tool (denylist overrides allowlist)
	allowed, reason := engine.EvaluateToolCall("query_dangerous_admin", nil)
	assert.False(t, allowed)
	assert.Contains(t, reason, "explicitly forbidden")

	// 3. Forbidden wildcard
	allowed, reason = engine.EvaluateToolCall("drop_tables", nil)
	assert.False(t, allowed)
	assert.Contains(t, reason, "explicitly forbidden")

	// 4. Not in allowlist
	allowed, reason = engine.EvaluateToolCall("unauthorized_tool", nil)
	assert.False(t, allowed)
	assert.Contains(t, reason, "not in the allowed tools list")
}

func TestPolicyEngine_ParameterConstraints(t *testing.T) {
	maxAge := 120.0
	minAge := 18.0

	cfg := &PolicyConfig{
		ToolRules: []ToolRule{
			{
				Name:    "create_account",
				Allowed: true,
				Constraints: map[string]ParameterConstraint{
					"username": {
						Required:  true,
						MinLength: 3,
						MaxLength: 20,
						Pattern:   `^[a-zA-Z0-9_]+$`,
					},
					"age": {
						MinValue: &minAge,
						MaxValue: &maxAge,
					},
				},
			},
		},
	}

	engine, err := NewPolicyEngine(cfg)
	require.NoError(t, err)

	// Valid call
	allowed, _ := engine.EvaluateToolCall("create_account", map[string]any{
		"username": "john_doe",
		"age":      25,
	})
	assert.True(t, allowed)

	// Missing required parameter
	allowed, reason := engine.EvaluateToolCall("create_account", map[string]any{
		"age": 25,
	})
	assert.False(t, allowed)
	assert.Contains(t, reason, "missing required parameter 'username'")

	// Regex constraint violation (contains invalid characters)
	allowed, reason = engine.EvaluateToolCall("create_account", map[string]any{
		"username": "invalid user!",
	})
	assert.False(t, allowed)
	assert.Contains(t, reason, "violates regex constraint")

	// Length constraints
	allowed, reason = engine.EvaluateToolCall("create_account", map[string]any{
		"username": "ab",
	})
	assert.False(t, allowed)
	assert.Contains(t, reason, "less than min 3")

	// MinValue bounds violation
	allowed, reason = engine.EvaluateToolCall("create_account", map[string]any{
		"username": "underage_user",
		"age":      15,
	})
	assert.False(t, allowed)
	assert.Contains(t, reason, "is less than min 18")
}

func TestPolicyEngine_RateLimiting(t *testing.T) {
	cfg := &PolicyConfig{
		ToolRules: []ToolRule{
			{
				Name:      "heavy_export",
				Allowed:   true,
				MaxPerMin: 2,
			},
		},
	}

	engine, err := NewPolicyEngine(cfg)
	require.NoError(t, err)

	// 1st call -> Allowed
	allowed, _ := engine.EvaluateToolCall("heavy_export", nil)
	assert.True(t, allowed)

	// 2nd call -> Allowed
	allowed, _ = engine.EvaluateToolCall("heavy_export", nil)
	assert.True(t, allowed)

	// 3rd call -> Rate limited
	allowed, reason := engine.EvaluateToolCall("heavy_export", nil)
	assert.False(t, allowed)
	assert.Contains(t, reason, "rate limit exceeded")
}
