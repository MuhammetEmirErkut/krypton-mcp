package guardrails

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode"
)

// ThreatSeverity classifies the risk level of detected injection attempts
type ThreatSeverity string

const (
	SeverityLow      ThreatSeverity = "LOW"
	SeverityMedium   ThreatSeverity = "MEDIUM"
	SeverityHigh     ThreatSeverity = "HIGH"
	SeverityCritical ThreatSeverity = "CRITICAL"
)

// ThreatCategory groups attack vectors
type ThreatCategory string

const (
	CategoryInstructionOverride ThreatCategory = "INSTRUCTION_OVERRIDE"
	CategoryPromptExtraction    ThreatCategory = "PROMPT_EXTRACTION"
	CategoryPersonaHijack       ThreatCategory = "PERSONA_HIJACK"
	CategoryDelimiterInjection  ThreatCategory = "DELIMITER_INJECTION"
	CategoryObfuscatedPayload   ThreatCategory = "OBFUSCATED_PAYLOAD"
	CategoryDestructiveCommand  ThreatCategory = "DESTRUCTIVE_COMMAND"
)

// ThreatReport contains detailed diagnostics on scan results
type ThreatReport struct {
	Detected        bool           `json:"detected"`
	Score           float64        `json:"score"` // 0.0 to 1.0
	Severity        ThreatSeverity `json:"severity,omitempty"`
	Category        ThreatCategory `json:"category,omitempty"`
	Reason          string         `json:"reason,omitempty"`
	MatchedPatterns []string       `json:"matched_patterns,omitempty"`
}

type injectionRule struct {
	category ThreatCategory
	severity ThreatSeverity
	weight   float64
	pattern  *regexp.Regexp
	reason   string
}

// InjectionDetector performs heuristic and pattern-based threat analysis
type InjectionDetector struct {
	rules           []injectionRule
	threshold       float64
	blockBase64     bool
	maxPayloadBytes int64
}

// NewInjectionDetector creates an initialized InjectionDetector with pre-compiled rules
func NewInjectionDetector() *InjectionDetector {
	detector := &InjectionDetector{
		rules:           make([]injectionRule, 0),
		threshold:       0.65, // Score threshold to trigger blocking
		blockBase64:     true,
		maxPayloadBytes: 1024 * 1024,
	}

	detector.initRules()
	return detector
}

func (d *InjectionDetector) initRules() {
	add := func(cat ThreatCategory, sev ThreatSeverity, weight float64, reason, patternStr string) {
		re := regexp.MustCompile("(?i)" + patternStr)
		d.rules = append(d.rules, injectionRule{
			category: cat,
			severity: sev,
			weight:   weight,
			pattern:  re,
			reason:   reason,
		})
	}

	// 1. Instruction Override & Jailbreaks
	add(CategoryInstructionOverride, SeverityCritical, 0.95,
		"Attempted to override system instructions",
		`\b(?:ignore|disregard|forget|bypass|override)\s+(?:all\s+|your\s+|the\s+|any\s+)?(?:previous|prior|system|initial|original|above)\s+(?:instructions|prompts|rules|commands|constraints)\b`)

	add(CategoryInstructionOverride, SeverityCritical, 0.90,
		"Jailbreak DAN / Developer mode exploit pattern",
		`\b(?:DAN\s+mode|developer\s+mode\s+enabled|do\s+anything\s+now|jailbreak\s+mode|unfiltered\s+mode)\b`)

	add(CategoryInstructionOverride, SeverityHigh, 0.80,
		"Attempted to reset AI state or instructions",
		`\b(?:reset\s+all\s+rules|start\s+fresh\s+without\s+restrictions|new\s+system\s+instruction:)\b`)

	// 2. System Prompt & Instruction Extraction
	add(CategoryPromptExtraction, SeverityHigh, 0.85,
		"Attempted to leak internal system instructions",
		`\b(?:repeat|print|output|display|show|reveal|echo)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|system\s+message|hidden\s+rules)\s*(?:verbatim|in\s+full|completely)?\b`)

	add(CategoryPromptExtraction, SeverityMedium, 0.70,
		"Indirect system prompt extraction attempt",
		`\b(?:what\s+(?:are|were)\s+your\s+(?:original|first|system)\s+instructions\??|what\s+is\s+written\s+above\??)\b`)

	// 3. Roleplay & Persona Hijacking
	add(CategoryPersonaHijack, SeverityHigh, 0.80,
		"Adversarial roleplay or persona hijack",
		`\b(?:you\s+are\s+now|pretend\s+you\s+are|act\s+as)\s+(?:an?\s+)?(?:unrestricted|evil|malicious|dark|unethical|jailbroken)\s+(?:AI|assistant|bot|hacker)\b`)

	// 4. Delimiter & Protocol Boundary Injection
	add(CategoryDelimiterInjection, SeverityCritical, 0.95,
		"Injected fake chat / system delimiter token",
		`<\|im_start\|>system|<\|im_end\|>|\[SYSTEM\]|<<SYS>>|---BEGIN SYSTEM INSTRUCTIONS---|\[INST\]\s*<<SYS>>`)

	// 5. Destructive Tool / System Commands
	add(CategoryDestructiveCommand, SeverityCritical, 0.90,
		"Dangerous shell destruction command",
		`\brm\s+-(?:r|f|rf|fr)\s+(?:[\/~]|\*|\.)|\bmkfs\.|\bdd\s+if=\/dev\/(?:zero|urandom)|\bformat\s+[a-zA-Z]:`)

	add(CategoryDestructiveCommand, SeverityHigh, 0.85,
		"Suspicious remote execution pipe",
		`\b(?:curl|wget)\s+[^|]+\|\s*(?:bash|sh|zsh|python|perl)\b`)
}

// NormalizeText strips zero-width non-printable unicode and collapses whitespace
func NormalizeText(input string) string {
	var sb strings.Builder
	sb.Grow(len(input))

	for _, r := range input {
		if unicode.Is(unicode.Variation_Selector, r) ||
			r == '\u200B' || r == '\u200C' || r == '\u200D' || r == '\uFEFF' || r == '\u00A0' {
			continue
		}
		sb.WriteRune(r)
	}

	return strings.Join(strings.Fields(sb.String()), " ")
}

// ScanText evaluates a string for potential injection attempts and returns a ThreatReport
func (d *InjectionDetector) ScanText(input string) ThreatReport {
	if strings.TrimSpace(input) == "" {
		return ThreatReport{Detected: false, Score: 0.0}
	}

	normalized := NormalizeText(input)

	var totalScore float64
	var matchedReasons []string
	var highestSeverity ThreatSeverity = SeverityLow
	var primaryCategory ThreatCategory

	for _, rule := range d.rules {
		if rule.pattern.MatchString(normalized) {
			if rule.weight > totalScore {
				totalScore = rule.weight
				highestSeverity = rule.severity
				primaryCategory = rule.category
			}
			matchedReasons = append(matchedReasons, rule.reason)
		}
	}

	// Check for obfuscated Base64 payloads containing potential instructions
	if d.blockBase64 {
		if b64Report := d.checkBase64Payloads(input); b64Report.Detected {
			if b64Report.Score > totalScore {
				totalScore = b64Report.Score
				highestSeverity = b64Report.Severity
				primaryCategory = b64Report.Category
			}
			matchedReasons = append(matchedReasons, b64Report.MatchedPatterns...)
		}
	}

	if totalScore >= d.threshold {
		reason := "Threat detected"
		if len(matchedReasons) > 0 {
			reason = matchedReasons[0]
		}

		return ThreatReport{
			Detected:        true,
			Score:           totalScore,
			Severity:        highestSeverity,
			Category:        primaryCategory,
			Reason:          reason,
			MatchedPatterns: matchedReasons,
		}
	}

	return ThreatReport{
		Detected: false,
		Score:    totalScore,
	}
}

// ScanArguments recursively inspects tool arguments for injection attempts
func (d *InjectionDetector) ScanArguments(args map[string]any) ThreatReport {
	for _, val := range args {
		report := d.scanGenericValue(val)
		if report.Detected {
			return report
		}
	}
	return ThreatReport{Detected: false, Score: 0.0}
}

func (d *InjectionDetector) scanGenericValue(v any) ThreatReport {
	switch val := v.(type) {
	case string:
		return d.ScanText(val)
	case map[string]any:
		return d.ScanArguments(val)
	case []any:
		for _, item := range val {
			report := d.scanGenericValue(item)
			if report.Detected {
				return report
			}
		}
	}
	return ThreatReport{Detected: false, Score: 0.0}
}

var b64WordRegex = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)

func (d *InjectionDetector) checkBase64Payloads(input string) ThreatReport {
	matches := b64WordRegex.FindAllString(input, 10)
	for _, m := range matches {
		decoded, err := base64.StdEncoding.DecodeString(m)
		if err == nil && len(decoded) > 12 {
			decodedStr := string(decoded)
			for _, rule := range d.rules {
				if rule.pattern.MatchString(decodedStr) {
					return ThreatReport{
						Detected:        true,
						Score:           0.90,
						Severity:        SeverityCritical,
						Category:        CategoryObfuscatedPayload,
						Reason:          "Base64 encoded injection payload: " + rule.reason,
						MatchedPatterns: []string{"Base64 payload contains: " + rule.reason},
					}
				}
			}
		}
	}
	return ThreatReport{Detected: false, Score: 0.0}
}
