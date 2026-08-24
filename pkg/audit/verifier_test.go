package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyLogFile_ValidLog(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "krypton_verifier_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "audit.jsonl")
	writer, err := NewFileWriter(logPath)
	require.NoError(t, err)

	for i := 0; i < 10; i++ {
		evt := NewAuditEvent(EventMCPRequest, "client", fmt.Sprintf("method_%d", i), []byte(fmt.Sprintf(`{"i":%d}`, i)), nil)
		require.NoError(t, writer.WriteEvent(evt))
	}
	require.NoError(t, writer.Close())

	report, err := VerifyLogFile(logPath, nil)
	require.NoError(t, err)
	require.NotNil(t, report)
	assert.True(t, report.Valid)
	assert.Equal(t, int64(10), report.TotalEvents)
	assert.NotEmpty(t, report.ComputedRoot)
	assert.Equal(t, report.ExpectedRoot, report.ComputedRoot)
	assert.Empty(t, report.Errors)
}

func TestVerifyLogFile_TamperedLog(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "krypton_verifier_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "audit.jsonl")
	writer, err := NewFileWriter(logPath)
	require.NoError(t, err)

	evt1 := NewAuditEvent(EventMCPRequest, "client", "read_db", []byte(`{"table":"users"}`), nil)
	evt2 := NewAuditEvent(EventMCPResponse, "gateway", "read_db", []byte(`{"count":42}`), nil)
	require.NoError(t, writer.WriteEvent(evt1))
	require.NoError(t, writer.WriteEvent(evt2))
	require.NoError(t, writer.Close())

	// Read and tamper with second line's payload hash
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)

	// Replace "read_db" with "drop_db" in the file without updating leaf_hash or merkle_root
	tamperedContent := []byte(string(content))
	tamperedContent = []byte(string(tamperedContent[:len(tamperedContent)-20]) + `"method":"drop_db"}` + "\n")
	require.NoError(t, os.WriteFile(logPath, tamperedContent, 0600))

	report, err := VerifyLogFile(logPath, nil)
	require.NoError(t, err)
	assert.False(t, report.Valid, "Tampered log file must fail verification")
	assert.NotEmpty(t, report.Errors)
}

func TestExportProofFromLog(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "krypton_verifier_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "audit.jsonl")
	writer, err := NewFileWriter(logPath)
	require.NoError(t, err)

	for i := 0; i < 8; i++ {
		evt := NewAuditEvent(EventToolExecution, "client", "execute", []byte(fmt.Sprintf(`{"step":%d}`, i)), nil)
		require.NoError(t, writer.WriteEvent(evt))
	}
	require.NoError(t, writer.Close())

	proof, err := ExportProofFromLog(logPath, 3)
	require.NoError(t, err)
	require.NotNil(t, proof)
	assert.Equal(t, int64(3), proof.LeafIndex)
	assert.True(t, VerifyProof(proof))
}
