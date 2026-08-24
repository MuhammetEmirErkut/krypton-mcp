package proxy

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessSupervisor_EchoLifecycle(t *testing.T) {
	// Use 'cat' which echoes stdin to stdout until stdin is closed
	sup := NewProcessSupervisor("cat", nil, map[string]string{"TEST_ENV": "1"}, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stdin, stdout, _, err := sup.Start(ctx)
	require.NoError(t, err)
	require.NotNil(t, stdin)
	require.NotNil(t, stdout)
	assert.True(t, sup.IsRunning())

	// Write to stdin
	testData := []byte("hello from krypton\n")
	_, err = stdin.Write(testData)
	require.NoError(t, err)

	// Read from stdout
	buf := make([]byte, len(testData))
	_, err = io.ReadFull(stdout, buf)
	require.NoError(t, err)
	assert.Equal(t, string(testData), string(buf))

	// Stop process
	err = sup.Stop()
	require.NoError(t, err)
	assert.False(t, sup.IsRunning())
}

func TestProcessSupervisor_NonExistentCommand(t *testing.T) {
	sup := NewProcessSupervisor("non_existent_binary_12345", nil, nil, "")
	_, _, _, err := sup.Start(context.Background())
	require.Error(t, err)
	assert.False(t, sup.IsRunning())
}

func TestProcessSupervisor_EmptyCommand(t *testing.T) {
	sup := NewProcessSupervisor("", nil, nil, "")
	_, _, _, err := sup.Start(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}
