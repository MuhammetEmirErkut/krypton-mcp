package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/krypton-mcp/krypton/internal/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func executeCommand(args ...string) (string, error) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs(args)

	err := cmd.Execute()
	return buf.String(), err
}

func TestVersionCmd(t *testing.T) {
	out, err := executeCommand("version")
	require.NoError(t, err)
	assert.Contains(t, out, "KryptonMCP")
	assert.Contains(t, out, version.Version)

	jsonOut, err := executeCommand("version", "--json")
	require.NoError(t, err)
	var info version.Info
	require.NoError(t, json.Unmarshal([]byte(jsonOut), &info))
	assert.Equal(t, version.Version, info.Version)
	assert.NotEmpty(t, info.GoVersion)
	assert.NotEmpty(t, info.OS)
	assert.NotEmpty(t, info.Arch)
}

func TestConfigInitAndValidateCmd(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "custom-krypton.yaml")

	// Init
	out, err := executeCommand("config", "init", "-o", configFile)
	require.NoError(t, err)
	assert.Contains(t, out, "Created template configuration file")

	// Verify file was written
	data, err := os.ReadFile(configFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), `version: "v1"`)

	// Re-init should fail because file already exists
	_, err = executeCommand("config", "init", "-o", configFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	// Validate valid file
	out, err = executeCommand("config", "validate", "-c", configFile)
	require.NoError(t, err)
	assert.Contains(t, out, "is valid")

	// Validate non-existent file
	_, err = executeCommand("config", "validate", "-c", filepath.Join(tempDir, "missing.yaml"))
	require.Error(t, err)

	// Validate invalid content file
	invalidFile := filepath.Join(tempDir, "invalid.yaml")
	require.NoError(t, os.WriteFile(invalidFile, []byte("version: 123\nserver:\n  transport: invalid"), 0600))
	_, err = executeCommand("config", "validate", "-c", invalidFile)
	require.Error(t, err)
}

func TestStartCmd_DryRun(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "krypton.yaml")

	_, err := executeCommand("config", "init", "-o", configFile)
	require.NoError(t, err)

	out, err := executeCommand("start", "--config", configFile, "--dry-run", "--transport", "sse", "--port", "9095")
	require.NoError(t, err)
	assert.Contains(t, out, "validated successfully")
	assert.Contains(t, strings.ToLower(out), "transport: sse")
}

func TestStartCmd_InvalidConfig(t *testing.T) {
	_, err := executeCommand("start", "--dry-run", "--transport", "unknown-proto")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid server transport")
}
