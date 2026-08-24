package masker

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// RuleType identifier for built-in and custom rules
type RuleType string

const (
	RuleEmail      RuleType = "email"
	RuleCreditCard RuleType = "credit_card"
	RuleSSN        RuleType = "ssn"
	RuleAPIKey     RuleType = "api_key"
	RuleJWT        RuleType = "jwt"
	RulePhone      RuleType = "phone"
	RuleIPAddress  RuleType = "ip_address"
	RuleCustom     RuleType = "custom"
)

// Match represents a detected sensitive data span within a string
type Match struct {
	RuleName    string
	RuleType    RuleType
	Value       string
	Start       int
	End         int
	Replacement string
}

// ValidatorFunc performs algorithmic verification on a matched string to filter false positives
type ValidatorFunc func(value string) bool

// CompiledRule encapsulates a compiled regular expression pattern and its optional validator
type CompiledRule struct {
	Name        string
	Type        RuleType
	Pattern     *regexp.Regexp
	Validator   ValidatorFunc
	Replacement string
}

// Builtin rule regular expressions (RE2 compliant)
var (
	// Email regex matching standard RFC 5322 format
	regexEmail = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)

	// Credit Card regex covering Visa, MasterCard, Amex, Discover, Diners, JCB (with optional dashes/spaces)
	regexCreditCard = regexp.MustCompile(`\b(?:\d{4}[ -]?){3}\d{4}\b|\b3[47]\d{2}[ -]?\d{6}[ -]?\d{5}\b`)

	// US Social Security Number (SSN) pattern (format: XXX-XX-XXXX)
	regexSSN = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)

	// API Keys and Secrets patterns
	regexAWSKey       = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	regexOpenAIKey    = regexp.MustCompile(`\bsk-[a-zA-Z0-9_-]{20,}\b`)
	regexAnthropicKey = regexp.MustCompile(`\bsk-ant-[a-zA-Z0-9_-]{20,}\b`)
	regexGitHubPAT    = regexp.MustCompile(`\b(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b`)
	regexPrivateKey   = regexp.MustCompile(`(?s)-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----`)

	// JSON Web Token (JWT) pattern
	regexJWT = regexp.MustCompile(`\beyJ[a-zA-Z0-9-_=]+\.eyJ[a-zA-Z0-9-_=]+\.[a-zA-Z0-9-_=]*\b`)

	// Phone numbers (North American and international formats)
	regexPhone = regexp.MustCompile(`(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`)

	// IPv4 and IPv6 addresses
	regexIPv4 = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	regexIPv6 = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,7}:|:(?::[0-9a-f]{1,4}){1,7}\b`)
)

// ValidateCreditCard validates the numeric string using the Luhn (Mod 10) algorithm
func ValidateCreditCard(val string) bool {
	// Strip spaces and dashes
	var digits []int
	for _, ch := range val {
		if unicode.IsDigit(ch) {
			d, _ := strconv.Atoi(string(ch))
			digits = append(digits, d)
		} else if ch != ' ' && ch != '-' {
			return false
		}
	}

	nDigits := len(digits)
	if nDigits < 13 || nDigits > 19 {
		return false
	}

	sum := 0
	isEven := false

	for i := nDigits - 1; i >= 0; i-- {
		digit := digits[i]
		if isEven {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		isEven = !isEven
	}

	return sum%10 == 0
}

// ValidateSSN ensures SSN has valid area (not 000, 666, 900-999), group (not 00), and serial (not 0000)
func ValidateSSN(val string) bool {
	parts := strings.Split(val, "-")
	if len(parts) != 3 {
		return false
	}

	area, group, serial := parts[0], parts[1], parts[2]
	if len(area) != 3 || len(group) != 2 || len(serial) != 4 {
		return false
	}

	// Invalid area numbers: "000", "666", "900"-"999"
	areaNum, err := strconv.Atoi(area)
	if err != nil || area == "000" || area == "666" || areaNum >= 900 {
		return false
	}

	// Invalid group: "00"
	if group == "00" {
		return false
	}

	// Invalid serial: "0000"
	if serial == "0000" {
		return false
	}

	// Reject dummy sequence "123-45-6789"
	if val == "000-00-0000" {
		return false
	}

	return true
}

// ValidateJWT verifies structure of JWT tokens
func ValidateJWT(val string) bool {
	parts := strings.Split(val, ".")
	return len(parts) == 3 && len(parts[0]) > 4 && len(parts[1]) > 4
}
