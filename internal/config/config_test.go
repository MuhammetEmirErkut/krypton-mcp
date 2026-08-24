package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	require.NotNil(t, cfg)

	assert.Equal(t, DefaultSchemaVersion, cfg.Version)
	assert.Equal(t, TransportStdio, cfg.Server.Transport)
	assert.Equal(t, "127.0.0.1", cfg.Server.Host)
	assert.Equal(t, 8080, cfg.Server.Port)
	assert.Equal(t, "info", cfg.Server.LogLevel)
	assert.True(t, cfg.Security.MaskingEnabled)
	assert.True(t, cfg.Security.GuardrailsEnabled)
	assert.True(t, cfg.Security.AuditEnabled)
	assert.False(t, cfg.Security.EphemeralCredsEnabled)
	assert.Equal(t, MaskModeTokenize, cfg.Masking.Mode)
	assert.Contains(t, cfg.Masking.BuiltinRules, "email")
	assert.Contains(t, cfg.Masking.BuiltinRules, "credit_card")
	assert.Equal(t, int64(1048576), cfg.Guardrails.MaxPromptSizeBytes)
	assert.Equal(t, "krypton-audit.log", cfg.Audit.LogPath)

	assert.NoError(t, cfg.Validate())
}

func TestLoad_ValidFile(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.yaml")

	yamlData := `
version: "v1"
server:
  transport: "sse"
  host: "0.0.0.0"
  port: 9090
  log_level: "debug"
downstream:
  command: "npx"
  args: ["-y", "@modelcontextprotocol/server-postgres"]
security:
  masking_enabled: true
  guardrails_enabled: false
  audit_enabled: true
  ephemeral_creds_enabled: true
masking:
  mode: "redact"
  builtin_rules: ["email"]
  custom_patterns:
    - name: "InternalID"
      pattern: "EMP-[0-9]{6}"
      replacement: "[INTERNAL_EMP]"
guardrails:
  block_injection: false
  block_exfiltration: true
  max_prompt_size_bytes: 2048
audit:
  log_path: "custom-audit.log"
  sign_enabled: false
`
	require.NoError(t, os.WriteFile(configFile, []byte(yamlData), 0600))

	cfg, err := Load(configFile)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "sse", cfg.Server.Transport)
	assert.Equal(t, "0.0.0.0", cfg.Server.Host)
	assert.Equal(t, 9090, cfg.Server.Port)
	assert.Equal(t, "debug", cfg.Server.LogLevel)
	assert.Equal(t, "npx", cfg.Downstream.Command)
	assert.Equal(t, []string{"-y", "@modelcontextprotocol/server-postgres"}, cfg.Downstream.Args)
	assert.False(t, cfg.Security.GuardrailsEnabled)
	assert.True(t, cfg.Security.EphemeralCredsEnabled)
	assert.Equal(t, "redact", cfg.Masking.Mode)
	assert.Len(t, cfg.Masking.CustomPatterns, 1)
	assert.Equal(t, "InternalID", cfg.Masking.CustomPatterns[0].Name)
	assert.Equal(t, "EMP-[0-9]{6}", cfg.Masking.CustomPatterns[0].Pattern)
	assert.Equal(t, "[INTERNAL_EMP]", cfg.Masking.CustomPatterns[0].Replacement)
	assert.Equal(t, "custom-audit.log", cfg.Audit.LogPath)
}

func TestLoad_NonExistentFile(t *testing.T) {
	cfg, err := Load("/non/existent/path/krypton.yaml")
	assert.Error(t, err)
	assert.Nil(t, cfg)
}

func TestLoad_InvalidYAML(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "invalid.yaml")

	require.NoError(t, os.WriteFile(configFile, []byte("invalid: yaml: : :"), 0600))

	cfg, err := Load(configFile)
	assert.Error(t, err)
	assert.Nil(t, cfg)
}

func TestValidate_Errors(t *testing.T) {
	tests := []struct {
		name        string
		modify      func(c *Config)
		expectedErr string
	}{
		{
			name: "empty version",
			modify: func(c *Config) {
				c.Version = ""
			},
			expectedErr: "config version must not be empty",
		},
		{
			name: "invalid transport",
			modify: func(c *Config) {
				c.Server.Transport = "grpc"
			},
			expectedErr: "invalid server transport 'grpc'",
		},
		{
			name: "invalid sse port low",
			modify: func(c *Config) {
				c.Server.Transport = TransportSSE
				c.Server.Port = 0
			},
			expectedErr: "invalid server port 0",
		},
		{
			name: "invalid sse port high",
			modify: func(c *Config) {
				c.Server.Transport = TransportSSE
				c.Server.Port = 70000
			},
			expectedErr: "invalid server port 70000",
		},
		{
			name: "empty sse host",
			modify: func(c *Config) {
				c.Server.Transport = TransportSSE
				c.Server.Host = ""
			},
			expectedErr: "server host must not be empty when using SSE transport",
		},
		{
			name: "invalid log level",
			modify: func(c *Config) {
				c.Server.LogLevel = "verbose"
			},
			expectedErr: "invalid log level 'verbose'",
		},
		{
			name: "invalid masking mode",
			modify: func(c *Config) {
				c.Masking.Mode = "strip"
			},
			expectedErr: "invalid masking mode 'strip'",
		},
		{
			name: "custom pattern empty name",
			modify: func(c *Config) {
				c.Masking.CustomPatterns = []CustomPattern{{Name: "", Pattern: ".*"}}
			},
			expectedErr: "custom pattern at index 0 has empty name",
		},
		{
			name: "custom pattern empty regex",
			modify: func(c *Config) {
				c.Masking.CustomPatterns = []CustomPattern{{Name: "test", Pattern: ""}}
			},
			expectedErr: "custom pattern 'test' has empty regex pattern",
		},
		{
			name: "invalid max prompt size",
			modify: func(c *Config) {
				c.Guardrails.MaxPromptSizeBytes = 0
			},
			expectedErr: "max_prompt_size_bytes must be greater than 0",
		},
		{
			name: "empty audit log path when audit enabled",
			modify: func(c *Config) {
				c.Security.AuditEnabled = true
				c.Audit.LogPath = ""
			},
			expectedErr: "audit log_path cannot be empty when audit is enabled",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tc.modify(cfg)
			err := cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("KRYPTON_SERVER_TRANSPORT", "sse")
	t.Setenv("KRYPTON_SERVER_HOST", "0.0.0.0")
	t.Setenv("KRYPTON_SERVER_PORT", "9999")
	t.Setenv("KRYPTON_SERVER_LOG_LEVEL", "debug")
	t.Setenv("KRYPTON_DOWNSTREAM_CMD", "docker run pg")
	t.Setenv("KRYPTON_SECURITY_MASKING_ENABLED", "false")
	t.Setenv("KRYPTON_SECURITY_GUARDRAILS_ENABLED", "false")
	t.Setenv("KRYPTON_SECURITY_AUDIT_ENABLED", "false")
	t.Setenv("KRYPTON_AUDIT_LOG_PATH", "env-audit.log")

	cfg, err := Load("")
	require.NoError(t, err)

	assert.Equal(t, "sse", cfg.Server.Transport)
	assert.Equal(t, "0.0.0.0", cfg.Server.Host)
	assert.Equal(t, 9999, cfg.Server.Port)
	assert.Equal(t, "debug", cfg.Server.LogLevel)
	assert.Equal(t, "docker run pg", cfg.Downstream.Command)
	assert.False(t, cfg.Security.MaskingEnabled)
	assert.False(t, cfg.Security.GuardrailsEnabled)
	assert.False(t, cfg.Security.AuditEnabled)
	assert.Equal(t, "env-audit.log", cfg.Audit.LogPath)
}

func TestGenerateTemplateYAML(t *testing.T) {
	tpl := GenerateTemplateYAML()
	assert.NotEmpty(t, tpl)

	var parsed Config
	err := yaml.Unmarshal([]byte(tpl), &parsed)
	require.NoError(t, err)
	assert.NoError(t, parsed.Validate())
}
