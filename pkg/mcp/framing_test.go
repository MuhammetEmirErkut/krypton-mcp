package mcp

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFramingWriter_WriteMessage(t *testing.T) {
	buf := new(bytes.Buffer)
	writer := NewFramingWriter(buf)

	req, err := NewRequest(NewIntID(1), "ping", nil)
	require.NoError(t, err)

	err = writer.WriteMessage(req)
	require.NoError(t, err)

	output := buf.String()
	assert.True(t, strings.HasSuffix(output, "\n"))
	assert.Contains(t, output, `"method":"ping"`)
	assert.Contains(t, output, `"id":1`)
}

func TestFramingWriter_ConcurrentWrites(t *testing.T) {
	buf := new(bytes.Buffer)
	writer := NewFramingWriter(buf)

	var wg sync.WaitGroup
	numRoutines := 50

	for i := 0; i < numRoutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			req, err := NewRequest(NewIntID(int64(id)), "ping", nil)
			if assert.NoError(t, err) {
				_ = writer.WriteMessage(req)
			}
		}(i)
	}

	wg.Wait()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Equal(t, numRoutines, len(lines))
}

func TestFramingReader_ReadRawLineAndMessage(t *testing.T) {
	input := "\n\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n"
	reader := NewFramingReader(strings.NewReader(input))

	ctx := context.Background()

	// First message (skips leading newlines)
	msg1, raw1, err := reader.ReadMessage(ctx)
	require.NoError(t, err)
	assert.Equal(t, "ping", msg1.Method)
	assert.Equal(t, int64(1), msg1.ID.IntVal)
	assert.Contains(t, string(raw1), `"method":"ping"`)

	// Second message (notification)
	msg2, _, err := reader.ReadMessage(ctx)
	require.NoError(t, err)
	assert.Equal(t, "notifications/initialized", msg2.Method)
	assert.Nil(t, msg2.ID)

	// End of file
	_, _, err = reader.ReadMessage(ctx)
	assert.Equal(t, io.EOF, err)
}

func TestFramingReader_InvalidJSON(t *testing.T) {
	input := "{invalid-json}\n"
	reader := NewFramingReader(strings.NewReader(input))

	_, raw, err := reader.ReadMessage(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "json unmarshal failed")
	assert.Equal(t, "{invalid-json}", string(raw))
}

func TestFramingReader_InvalidJSONRPCVersion(t *testing.T) {
	input := "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"test\"}\n"
	reader := NewFramingReader(strings.NewReader(input))

	_, _, err := reader.ReadMessage(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported jsonrpc version")
}

func TestFramingReader_MaxMessageSizeLimit(t *testing.T) {
	// 50-byte max limit
	reader := NewFramingReaderWithSize(strings.NewReader(strings.Repeat("A", 100)+"\n"), 50)

	_, _, err := reader.ReadMessage(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMessageTooLarge)
}

func TestFramingReader_ContextCancellation(t *testing.T) {
	pr, _ := io.Pipe() // Pipe will block on read since nothing is written
	reader := NewFramingReader(pr)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, _, err := reader.ReadMessage(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestFraming_PipeIntegration(t *testing.T) {
	pr, pw := io.Pipe()
	writer := NewFramingWriter(pw)
	reader := NewFramingReader(pr)

	go func() {
		defer pw.Close()
		req, _ := NewRequest(NewStringID("req-99"), "tools/list", nil)
		_ = writer.WriteMessage(req)
	}()

	msg, _, err := reader.ReadMessage(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "tools/list", msg.Method)
	assert.Equal(t, "req-99", msg.ID.StrVal)
}
