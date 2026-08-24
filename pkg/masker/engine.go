package masker

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/krypton-mcp/krypton/internal/config"
)

// RuleEngine coordinates pattern matching and sensitive data detection
type RuleEngine struct {
	rules []CompiledRule
}

// NewRuleEngine initializes a RuleEngine with configured builtin and custom rules
func NewRuleEngine(cfg *config.MaskingConfig) (*RuleEngine, error) {
	if cfg == nil {
		defaultCfg := config.DefaultConfig().Masking
		cfg = &defaultCfg
	}

	engine := &RuleEngine{
		rules: make([]CompiledRule, 0),
	}

	// Register built-in rules
	for _, ruleName := range cfg.BuiltinRules {
		switch strings.ToLower(ruleName) {
		case string(RuleEmail):
			engine.rules = append(engine.rules, CompiledRule{
				Name:    "email",
				Type:    RuleEmail,
				Pattern: regexEmail,
			})
		case string(RuleCreditCard):
			engine.rules = append(engine.rules, CompiledRule{
				Name:      "credit_card",
				Type:      RuleCreditCard,
				Pattern:   regexCreditCard,
				Validator: ValidateCreditCard,
			})
		case string(RuleSSN):
			engine.rules = append(engine.rules, CompiledRule{
				Name:      "ssn",
				Type:      RuleSSN,
				Pattern:   regexSSN,
				Validator: ValidateSSN,
			})
		case string(RuleAPIKey):
			engine.rules = append(engine.rules,
				CompiledRule{Name: "aws_key", Type: RuleAPIKey, Pattern: regexAWSKey},
				CompiledRule{Name: "openai_key", Type: RuleAPIKey, Pattern: regexOpenAIKey},
				CompiledRule{Name: "anthropic_key", Type: RuleAPIKey, Pattern: regexAnthropicKey},
				CompiledRule{Name: "github_pat", Type: RuleAPIKey, Pattern: regexGitHubPAT},
				CompiledRule{Name: "private_key", Type: RuleAPIKey, Pattern: regexPrivateKey},
			)
		case string(RuleJWT):
			engine.rules = append(engine.rules, CompiledRule{
				Name:      "jwt",
				Type:      RuleJWT,
				Pattern:   regexJWT,
				Validator: ValidateJWT,
			})
		case string(RulePhone):
			engine.rules = append(engine.rules, CompiledRule{
				Name:    "phone",
				Type:    RulePhone,
				Pattern: regexPhone,
			})
		case string(RuleIPAddress):
			engine.rules = append(engine.rules,
				CompiledRule{Name: "ipv4", Type: RuleIPAddress, Pattern: regexIPv4},
				CompiledRule{Name: "ipv6", Type: RuleIPAddress, Pattern: regexIPv6},
			)
		}
	}

	// Register custom patterns
	for _, cp := range cfg.CustomPatterns {
		compiled, err := regexp.Compile(cp.Pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile custom pattern '%s': %w", cp.Name, err)
		}

		engine.rules = append(engine.rules, CompiledRule{
			Name:        cp.Name,
			Type:        RuleCustom,
			Pattern:     compiled,
			Replacement: cp.Replacement,
		})
	}

	return engine, nil
}

// Rules returns the list of currently compiled rules
func (e *RuleEngine) Rules() []CompiledRule {
	return e.rules
}

// Scan identifies all sensitive data matches within the input text, resolving overlaps
func (e *RuleEngine) Scan(input string) []Match {
	if input == "" || len(e.rules) == 0 {
		return nil
	}

	var allMatches []Match

	for _, rule := range e.rules {
		indices := rule.Pattern.FindAllStringIndex(input, -1)
		for _, loc := range indices {
			start, end := loc[0], loc[1]
			val := input[start:end]

			// Run algorithmic validator if configured
			if rule.Validator != nil && !rule.Validator(val) {
				continue
			}

			allMatches = append(allMatches, Match{
				RuleName:    rule.Name,
				RuleType:    rule.Type,
				Value:       val,
				Start:       start,
				End:         end,
				Replacement: rule.Replacement,
			})
		}
	}

	if len(allMatches) == 0 {
		return nil
	}

	return resolveOverlaps(allMatches)
}

// ContainsSensitiveData performs an optimized scan returning true on first valid match
func (e *RuleEngine) ContainsSensitiveData(input string) bool {
	if input == "" {
		return false
	}

	for _, rule := range e.rules {
		indices := rule.Pattern.FindAllStringIndex(input, -1)
		for _, loc := range indices {
			val := input[loc[0]:loc[1]]
			if rule.Validator == nil || rule.Validator(val) {
				return true
			}
		}
	}

	return false
}

// resolveOverlaps sorts matches and removes overlapping or sub-spans
func resolveOverlaps(matches []Match) []Match {
	if len(matches) <= 1 {
		return matches
	}

	// Sort by start index ascending, then by match length descending
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Start == matches[j].Start {
			return (matches[i].End - matches[i].Start) > (matches[j].End - matches[j].Start)
		}
		return matches[i].Start < matches[j].Start
	})

	resolved := make([]Match, 0, len(matches))
	lastEnd := -1

	for _, m := range matches {
		if m.Start >= lastEnd {
			resolved = append(resolved, m)
			lastEnd = m.End
		}
	}

	return resolved
}
