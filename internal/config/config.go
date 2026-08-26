package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/krypton-mcp/krypton/pkg/guardrails"
	"gopkg.in/yaml.v3"
)

const (
	// DefaultSchemaVersion represents the current configuration format version
	DefaultSchemaVersion = "v1"
	// TransportStdio specifies stdio-based JSON-RPC transport
	TransportStdio = "stdio"
	// TransportSSE specifies Server-Sent Events / HTTP transport
	TransportSSE = "sse"
	// TransportHTTP specifies HTTP-based JSON-RPC transport for downstream
	TransportHTTP = "http"

	// MaskModeTokenize replaces sensitive data with reversible surrogate tokens
	MaskModeTokenize = "tokenize"
	// MaskModeRedact replaces sensitive data with static markers like [REDACTED]
	MaskModeRedact = "redact"
	// MaskModeHash replaces sensitive data with one-way salted hashes
	MaskModeHash = "hash"
)

// CustomPattern allows users to supply custom regex rules for masking
type CustomPattern struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Pattern     string `yaml:"pattern" json:"pattern"`
	Replacement string `yaml:"replacement,omitempty" json:"replacement,omitempty"`
}

// ServerConfig configures the gateway listener and transport
type ServerConfig struct {
	Transport string `yaml:"transport" json:"transport"`
	Host      string `yaml:"host" json:"host"`
	Port      int    `yaml:"port" json:"port"`
	LogLevel  string `yaml:"log_level" json:"log_level"`
}

// DownstreamConfig defines the target MCP sub-process or remote HTTP/SSE service to proxy
type DownstreamConfig struct {
	Transport  string            `yaml:"transport,omitempty" json:"transport,omitempty"`
	URL        string            `yaml:"url,omitempty" json:"url,omitempty"`
	Command    string            `yaml:"command,omitempty" json:"command,omitempty"`
	Args       []string          `yaml:"args,omitempty" json:"args,omitempty"`
	Env        map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	WorkingDir string            `yaml:"working_dir,omitempty" json:"working_dir,omitempty"`
}

// SecurityConfig toggles core security subsystems
type SecurityConfig struct {
	MaskingEnabled        bool `yaml:"masking_enabled" json:"masking_enabled"`
	GuardrailsEnabled     bool `yaml:"guardrails_enabled" json:"guardrails_enabled"`
	AuditEnabled          bool `yaml:"audit_enabled" json:"audit_enabled"`
	EphemeralCredsEnabled bool `yaml:"ephemeral_creds_enabled" json:"ephemeral_creds_enabled"`
}

// MaskingConfig controls PII and secret redaction behavior
type MaskingConfig struct {
	Mode           string          `yaml:"mode" json:"mode"`
	BuiltinRules   []string        `yaml:"builtin_rules" json:"builtin_rules"`
	CustomPatterns []CustomPattern `yaml:"custom_patterns,omitempty" json:"custom_patterns,omitempty"`
	ExcludedFields []string        `yaml:"excluded_fields,omitempty" json:"excluded_fields,omitempty"`
}

// GuardrailsConfig defines prompt injection, RBAC, and exfiltration policies
type GuardrailsConfig struct {
	BlockInjection     bool                  `yaml:"block_injection" json:"block_injection"`
	BlockExfiltration  bool                  `yaml:"block_exfiltration" json:"block_exfiltration"`
	MaxPromptSizeBytes int64                 `yaml:"max_prompt_size_bytes" json:"max_prompt_size_bytes"`
	AllowedTools       []string              `yaml:"allowed_tools,omitempty" json:"allowed_tools,omitempty"`
	DeniedTools        []string              `yaml:"denied_tools,omitempty" json:"denied_tools,omitempty"`
	ForbiddenTools     []string              `yaml:"forbidden_tools,omitempty" json:"forbidden_tools,omitempty"`
	ToolRules          []guardrails.ToolRule `yaml:"tool_rules,omitempty" json:"tool_rules,omitempty"`
}

// ToPolicyConfig converts GuardrailsConfig into a PolicyConfig for the guardrails engine
func (g *GuardrailsConfig) ToPolicyConfig() *guardrails.PolicyConfig {
	forbidden := make([]string, 0, len(g.ForbiddenTools)+len(g.DeniedTools))
	forbidden = append(forbidden, g.ForbiddenTools...)
	forbidden = append(forbidden, g.DeniedTools...)

	return &guardrails.PolicyConfig{
		AllowedTools:   g.AllowedTools,
		ForbiddenTools: forbidden,
		ToolRules:      g.ToolRules,
	}
}

// AuditConfig specifies tamper-evident Merkle logging settings
type AuditConfig struct {
	LogPath        string `yaml:"log_path" json:"log_path"`
	SignEnabled    bool   `yaml:"sign_enabled" json:"sign_enabled"`
	SigningKeyPath string `yaml:"signing_key_path,omitempty" json:"signing_key_path,omitempty"`
	PublicKeyPath  string `yaml:"public_key_path,omitempty" json:"public_key_path,omitempty"`
}

// Config is the root configuration structure for KryptonMCP
type Config struct {
	Version    string           `yaml:"version" json:"version"`
	Server     ServerConfig     `yaml:"server" json:"server"`
	Downstream DownstreamConfig `yaml:"downstream" json:"downstream"`
	Security   SecurityConfig   `yaml:"security" json:"security"`
	Masking    MaskingConfig    `yaml:"masking" json:"masking"`
	Guardrails GuardrailsConfig `yaml:"guardrails" json:"guardrails"`
	Audit      AuditConfig      `yaml:"audit" json:"audit"`
}

// DefaultConfig returns a fully initialized Config with enterprise defaults
func DefaultConfig() *Config {
	return &Config{
		Version: DefaultSchemaVersion,
		Server: ServerConfig{
			Transport: TransportStdio,
			Host:      "127.0.0.1",
			Port:      8080,
			LogLevel:  "info",
		},
		Downstream: DownstreamConfig{
			Transport: TransportStdio,
			URL:       "",
			Command:   "",
			Args:      []string{},
			Env:       make(map[string]string),
		},
		Security: SecurityConfig{
			MaskingEnabled:        true,
			GuardrailsEnabled:     true,
			AuditEnabled:          true,
			EphemeralCredsEnabled: false,
		},
		Masking: MaskingConfig{
			Mode: MaskModeTokenize,
			BuiltinRules: []string{
				"email",
				"credit_card",
				"ssn",
				"api_key",
				"jwt",
				"phone",
				"ip_address",
			},
			CustomPatterns: []CustomPattern{},
			ExcludedFields: []string{},
		},
		Guardrails: GuardrailsConfig{
			BlockInjection:     true,
			BlockExfiltration:  true,
			MaxPromptSizeBytes: 1024 * 1024, // 1MB
			AllowedTools:       []string{},
			DeniedTools:        []string{},
			ForbiddenTools:     []string{},
			ToolRules:          []guardrails.ToolRule{},
		},
		Audit: AuditConfig{
			LogPath:        "krypton-audit.log",
			SignEnabled:    true,
			SigningKeyPath: "",
			PublicKeyPath:  "",
		},
	}
}

// Load reads and parses a YAML configuration file, overlaying environment variables
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file '%s': %w", path, err)
		}

		decoder := yaml.NewDecoder(strings.NewReader(string(data)))
		decoder.KnownFields(true)
		if err := decoder.Decode(cfg); err != nil {
			return nil, fmt.Errorf("failed to parse yaml config '%s': %w", path, err)
		}
	}

	cfg.applyEnvOverrides()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// applyEnvOverrides allows overriding config values via environment variables
func (c *Config) applyEnvOverrides() {
	if val := os.Getenv("KRYPTON_SERVER_TRANSPORT"); val != "" {
		c.Server.Transport = strings.ToLower(val)
	}
	if val := os.Getenv("KRYPTON_SERVER_HOST"); val != "" {
		c.Server.Host = val
	}
	if val := os.Getenv("KRYPTON_SERVER_PORT"); val != "" {
		if p, err := strconv.Atoi(val); err == nil {
			c.Server.Port = p
		}
	}
	if val := os.Getenv("KRYPTON_SERVER_LOG_LEVEL"); val != "" {
		c.Server.LogLevel = strings.ToLower(val)
	}
	if val := os.Getenv("KRYPTON_DOWNSTREAM_TRANSPORT"); val != "" {
		c.Downstream.Transport = strings.ToLower(val)
	}
	if val := os.Getenv("KRYPTON_DOWNSTREAM_URL"); val != "" {
		c.Downstream.URL = val
	}
	if val := os.Getenv("KRYPTON_DOWNSTREAM_CMD"); val != "" {
		c.Downstream.Command = val
	}
	if val := os.Getenv("KRYPTON_SECURITY_MASKING_ENABLED"); val != "" {
		c.Security.MaskingEnabled = parseBoolSafe(val, c.Security.MaskingEnabled)
	}
	if val := os.Getenv("KRYPTON_SECURITY_GUARDRAILS_ENABLED"); val != "" {
		c.Security.GuardrailsEnabled = parseBoolSafe(val, c.Security.GuardrailsEnabled)
	}
	if val := os.Getenv("KRYPTON_SECURITY_AUDIT_ENABLED"); val != "" {
		c.Security.AuditEnabled = parseBoolSafe(val, c.Security.AuditEnabled)
	}
	if val := os.Getenv("KRYPTON_AUDIT_LOG_PATH"); val != "" {
		c.Audit.LogPath = val
	}
}

func parseBoolSafe(val string, defaultVal bool) bool {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return defaultVal
	}
}

// Validate checks the configuration for consistency and valid constraints
func (c *Config) Validate() error {
	if c.Version == "" {
		return errors.New("config version must not be empty")
	}

	switch c.Server.Transport {
	case TransportStdio, TransportSSE:
		// valid
	default:
		return fmt.Errorf("invalid server transport '%s': must be 'stdio' or 'sse'", c.Server.Transport)
	}

	if c.Server.Transport == TransportSSE {
		if c.Server.Port < 1 || c.Server.Port > 65535 {
			return fmt.Errorf("invalid server port %d: must be between 1 and 65535", c.Server.Port)
		}
		if c.Server.Host == "" {
			return errors.New("server host must not be empty when using SSE transport")
		}
	}

	if c.Downstream.Transport == "" {
		if c.Downstream.URL != "" {
			c.Downstream.Transport = TransportHTTP
		} else {
			c.Downstream.Transport = TransportStdio
		}
	}

	if c.Downstream.URL != "" {
		if !strings.HasPrefix(c.Downstream.URL, "http://") && !strings.HasPrefix(c.Downstream.URL, "https://") {
			return fmt.Errorf("invalid downstream url '%s': must start with http:// or https://", c.Downstream.URL)
		}
	}

	switch strings.ToLower(c.Server.LogLevel) {
	case "debug", "info", "warn", "error":
		// valid
	default:
		return fmt.Errorf("invalid log level '%s': must be debug, info, warn, or error", c.Server.LogLevel)
	}

	switch c.Masking.Mode {
	case MaskModeTokenize, MaskModeRedact, MaskModeHash:
		// valid
	default:
		return fmt.Errorf("invalid masking mode '%s': must be tokenize, redact, or hash", c.Masking.Mode)
	}

	for i, cp := range c.Masking.CustomPatterns {
		if strings.TrimSpace(cp.Name) == "" {
			return fmt.Errorf("custom pattern at index %d has empty name", i)
		}
		if strings.TrimSpace(cp.Pattern) == "" {
			return fmt.Errorf("custom pattern '%s' has empty regex pattern", cp.Name)
		}
	}

	if c.Guardrails.MaxPromptSizeBytes <= 0 {
		return errors.New("max_prompt_size_bytes must be greater than 0")
	}

	if c.Security.AuditEnabled && strings.TrimSpace(c.Audit.LogPath) == "" {
		return errors.New("audit log_path cannot be empty when audit is enabled")
	}

	return nil
}

// GenerateTemplateYAML returns a clean, fully commented YAML configuration string
func GenerateTemplateYAML() string {
	return `# ==============================================================================
# KryptonMCP - Zero-Trust Security Gateway for AI Agents Configuration
# ==============================================================================
version: "v1"

server:
  # Transport mode: "stdio" (for IDEs / sub-process spawning) or "sse" (HTTP Server-Sent Events)
  transport: "stdio"
  host: "127.0.0.1"
  port: 8080
  # Log level: "debug", "info", "warn", "error"
  log_level: "info"

downstream:
  # Downstream MCP transport: "stdio" (sub-process) or "http" (remote network service)
  transport: "stdio"
  # Target remote MCP endpoint (when transport is "http")
  # url: "http://localhost:8001/rpc"
  # Downstream MCP server command to proxy (when transport is "stdio")
  # Example: "npx" with args ["-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/mydb"]
  command: ""
  args: []
  env: {}
  working_dir: ""

security:
  masking_enabled: true
  guardrails_enabled: true
  audit_enabled: true
  ephemeral_creds_enabled: false

masking:
  # Masking mode: "tokenize" (reversible surrogate tokens), "redact" ([REDACTED]), or "hash" (salted SHA-256)
  mode: "tokenize"
  builtin_rules:
    - "email"
    - "credit_card"
    - "ssn"
    - "api_key"
    - "jwt"
    - "phone"
    - "ip_address"
  custom_patterns: []
  excluded_fields: []

guardrails:
  block_injection: true
  block_exfiltration: true
  max_prompt_size_bytes: 1048576 # 1 MB
  # Declarative Tool RBAC
  allowed_tools:
    - "*"
  denied_tools:
    - "drop_*"
    - "delete_database"
    - "execute_raw_shell"

audit:
  log_path: "krypton-audit.log"
  sign_enabled: true
  signing_key_path: ""
  public_key_path: ""
`
}
