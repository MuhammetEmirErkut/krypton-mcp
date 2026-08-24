package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogWriter_MemoryWriter(t *testing.T) {
	writer, buf := NewMemoryWriter()

	evt1 := NewAuditEvent(EventMCPRequest, "client", "tools/call", []byte(`{"tool":"query_users"}`), map[string]any{"user": "alice"})
	err := writer.WriteEvent(evt1)
	require.NoError(t, err)

	evt2 := NewAuditEvent(EventMCPResponse, "gateway", "tools/call", []byte(`{"status":"ok"}`), nil)
	err = writer.WriteEvent(evt2)
	require.NoError(t, err)

	assert.Equal(t, int64(2), writer.Tree().LeafCount())
	assert.NotEmpty(t, evt1.MerkleRoot)
	assert.NotEmpty(t, evt2.MerkleRoot)
	assert.Equal(t, int64(0), evt1.Index)
	assert.Equal(t, int64(1), evt2.Index)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 2)

	var parsed1, parsed2 AuditEvent
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &parsed1))
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &parsed2))

	assert.Equal(t, evt1.ID, parsed1.ID)
	assert.Equal(t, evt2.ID, parsed2.ID)
}

func TestLogWriter_FileWriter(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "krypton_audit_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "audit.jsonl")
	writer, err := NewFileWriter(logPath)
	require.NoError(t, err)

	evt := NewAuditEvent(EventSecurityViolation, "gateway", "tools/call", []byte(`{"attack":"sql_injection"}`), map[string]any{"threat_score": 0.95})
	err = writer.WriteEvent(evt)
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	// Verify file contents
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Contains(t, string(content), "security_violation")
	assert.Contains(t, string(content), evt.ID)
}
