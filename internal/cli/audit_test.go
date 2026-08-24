package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/krypton-mcp/krypton/pkg/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditCLI_KeygenAndVerify(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "krypton_cli_audit_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// 1. Run keygen command
	rootCmd := NewRootCmd()
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"audit", "keygen", "--out-dir", tmpDir})

	err = rootCmd.Execute()
	require.NoError(t, err)
	assert.FileExists(t, filepath.Join(tmpDir, "krypton_audit.key"))
	assert.FileExists(t, filepath.Join(tmpDir, "krypton_audit.pub"))

	// 2. Create sample audit.jsonl
	logPath := filepath.Join(tmpDir, "audit.jsonl")
	writer, err := audit.NewFileWriter(logPath)
	require.NoError(t, err)
	for i := 0; i < 5; i++ {
		evt := audit.NewAuditEvent(audit.EventMCPRequest, "client", fmt.Sprintf("cmd_%d", i), []byte(fmt.Sprintf(`{"val":%d}`, i)), nil)
		require.NoError(t, writer.WriteEvent(evt))
	}
	require.NoError(t, writer.Close())

	// 3. Run verify command
	verifyCmd := NewRootCmd()
	verifyCmd.SetOut(buf)
	verifyCmd.SetErr(buf)
	verifyCmd.SetArgs([]string{"audit", "verify", "--log-file", logPath})
	err = verifyCmd.Execute()
	require.NoError(t, err)

	// 4. Run proof command
	proofCmd := NewRootCmd()
	proofCmd.SetOut(buf)
	proofCmd.SetErr(buf)
	proofCmd.SetArgs([]string{"audit", "proof", "--log-file", logPath, "--index", "2"})
	err = proofCmd.Execute()
	require.NoError(t, err)
}
