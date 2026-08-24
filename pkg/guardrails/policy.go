package guardrails

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ParameterConstraint defines validation rules for a specific tool argument
type ParameterConstraint struct {
	Required  bool           `yaml:"required" json:"required"`
	Pattern   string         `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	MinLength int            `yaml:"min_length,omitempty" json:"min_length,omitempty"`
	MaxLength int            `yaml:"max_length,omitempty" json:"max_length,omitempty"`
	MaxValue  *float64       `yaml:"max_value,omitempty" json:"max_value,omitempty"`
	MinValue  *float64       `yaml:"min_value,omitempty" json:"min_value,omitempty"`
	compiled  *regexp.Regexp
}

// ToolRule defines access policies and argument constraints for an individual tool
type ToolRule struct {
	Name        string                         `yaml:"name" json:"name"`
	Allowed     bool                           `yaml:"allowed" json:"allowed"`
	MaxPerMin   int                            `yaml:"max_per_min,omitempty" json:"max_per_min,omitempty"`
	Constraints map[string]ParameterConstraint `yaml:"constraints,omitempty" json:"constraints,omitempty"`
}

// PolicyConfig encapsulates declarative guardrail rules
type PolicyConfig struct {
	AllowedTools   []string   `yaml:"allowed_tools" json:"allowed_tools"`
	ForbiddenTools []string   `yaml:"forbidden_tools" json:"forbidden_tools"`
	ToolRules      []ToolRule `yaml:"tool_rules,omitempty" json:"tool_rules,omitempty"`
}

// PolicyEngine enforces RBAC, allowlists, denylists, parameter constraints, and rate limits
type PolicyEngine struct {
	mu             sync.Mutex
	allowedTools   []string
	forbiddenTools []string
	toolRules      map[string]ToolRule
	callHistory    map[string][]time.Time
}

// NewPolicyEngine creates an initialized PolicyEngine
func NewPolicyEngine(cfg *PolicyConfig) (*PolicyEngine, error) {
	engine := &PolicyEngine{
		allowedTools:   make([]string, 0),
		forbiddenTools: make([]string, 0),
		toolRules:      make(map[string]ToolRule),
		callHistory:    make(map[string][]time.Time),
	}

	if cfg != nil {
		engine.allowedTools = append(engine.allowedTools, cfg.AllowedTools...)
		engine.forbiddenTools = append(engine.forbiddenTools, cfg.ForbiddenTools...)

		for _, tr := range cfg.ToolRules {
			for k, c := range tr.Constraints {
				if c.Pattern != "" {
					re, err := regexp.Compile(c.Pattern)
					if err != nil {
						return nil, fmt.Errorf("invalid regex constraint for tool '%s' arg '%s': %w", tr.Name, k, err)
					}
					c.compiled = re
					tr.Constraints[k] = c
				}
			}
			engine.toolRules[tr.Name] = tr
		}
	}

	return engine, nil
}

// EvaluateToolCall checks if a tool invocation complies with RBAC, denylists, constraints, and rate limits
func (e *PolicyEngine) EvaluateToolCall(toolName string, args map[string]any) (allowed bool, reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// 1. Check explicit forbidden tools (denylist takes precedence)
	for _, forbidden := range e.forbiddenTools {
		if matchToolPattern(forbidden, toolName) {
			return false, fmt.Sprintf("tool '%s' is explicitly forbidden by security policy", toolName)
		}
	}

	// 2. Check allowlist if configured
	if len(e.allowedTools) > 0 {
		isAllowed := false
		for _, allowedPattern := range e.allowedTools {
			if matchToolPattern(allowedPattern, toolName) {
				isAllowed = true
				break
			}
		}
		if !isAllowed {
			return false, fmt.Sprintf("tool '%s' is not in the allowed tools list", toolName)
		}
	}

	// 3. Check tool-specific rule
	rule, hasRule := e.toolRules[toolName]
	if hasRule {
		if !rule.Allowed {
			return false, fmt.Sprintf("tool '%s' execution is disabled by policy rule", toolName)
		}

		// Check rate limiting
		if rule.MaxPerMin > 0 {
			now := time.Now()
			oneMinAgo := now.Add(-1 * time.Minute)

			// Clean up old entries
			var recent []time.Time
			for _, t := range e.callHistory[toolName] {
				if t.After(oneMinAgo) {
					recent = append(recent, t)
				}
			}
			e.callHistory[toolName] = recent

			if len(recent) >= rule.MaxPerMin {
				return false, fmt.Sprintf("rate limit exceeded for tool '%s' (%d calls/min max)", toolName, rule.MaxPerMin)
			}
			e.callHistory[toolName] = append(e.callHistory[toolName], now)
		}

		// Check parameter constraints
		for paramName, constraint := range rule.Constraints {
			val, exists := args[paramName]
			if constraint.Required && (!exists || val == nil) {
				return false, fmt.Sprintf("missing required parameter '%s' for tool '%s'", paramName, toolName)
			}

			if exists && val != nil {
				if strVal, ok := val.(string); ok {
					if constraint.MinLength > 0 && len(strVal) < constraint.MinLength {
						return false, fmt.Sprintf("parameter '%s' length %d is less than min %d", paramName, len(strVal), constraint.MinLength)
					}
					if constraint.MaxLength > 0 && len(strVal) > constraint.MaxLength {
						return false, fmt.Sprintf("parameter '%s' length %d exceeds max %d", paramName, len(strVal), constraint.MaxLength)
					}
					if constraint.compiled != nil && !constraint.compiled.MatchString(strVal) {
						return false, fmt.Sprintf("parameter '%s' value violates regex constraint pattern", paramName)
					}
				}

				if numVal, ok := toFloat64(val); ok {
					if constraint.MinValue != nil && numVal < *constraint.MinValue {
						return false, fmt.Sprintf("parameter '%s' value %v is less than min %v", paramName, numVal, *constraint.MinValue)
					}
					if constraint.MaxValue != nil && numVal > *constraint.MaxValue {
						return false, fmt.Sprintf("parameter '%s' value %v exceeds max %v", paramName, numVal, *constraint.MaxValue)
					}
				}
			}
		}
	}

	return true, ""
}

func matchToolPattern(pattern, toolName string) bool {
	matched, err := filepath.Match(pattern, toolName)
	if err == nil && matched {
		return true
	}
	return strings.EqualFold(pattern, toolName)
}

func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}
