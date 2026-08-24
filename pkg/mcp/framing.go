package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	// DefaultMaxMessageSize is the maximum allowed single message size (16MB)
	DefaultMaxMessageSize = 16 * 1024 * 1024
	// InitialBufferSize for the streaming scanner
	InitialBufferSize = 64 * 1024
)

var (
	// ErrMessageTooLarge is returned when an incoming line exceeds max allowed buffer
	ErrMessageTooLarge = errors.New("mcp framing: message exceeds maximum allowed size")
)

// FramingReader parses newline-delimited JSON-RPC messages from an io.Reader
type FramingReader struct {
	reader  *bufio.Reader
	maxSize int
}

// NewFramingReader creates a new FramingReader
func NewFramingReader(r io.Reader) *FramingReader {
	return NewFramingReaderWithSize(r, DefaultMaxMessageSize)
}

// NewFramingReaderWithSize creates a FramingReader with a custom max message size limit
func NewFramingReaderWithSize(r io.Reader, maxSize int) *FramingReader {
	if maxSize <= 0 {
		maxSize = DefaultMaxMessageSize
	}
	return &FramingReader{
		reader:  bufio.NewReaderSize(r, InitialBufferSize),
		maxSize: maxSize,
	}
}

// ReadRawLine reads a single newline-delimited line of bytes, stripping trailing CRLF
func (fr *FramingReader) ReadRawLine(ctx context.Context) ([]byte, error) {
	type readResult struct {
		line []byte
		err  error
	}

	resCh := make(chan readResult, 1)

	go func() {
		var fullLine bytes.Buffer

		for {
			chunk, isPrefix, err := fr.reader.ReadLine()
			if err != nil {
				resCh <- readResult{err: err}
				return
			}

			fullLine.Write(chunk)
			if fullLine.Len() > fr.maxSize {
				resCh <- readResult{err: ErrMessageTooLarge}
				return
			}

			if !isPrefix {
				break
			}
		}

		line := bytes.TrimSpace(fullLine.Bytes())
		resCh <- readResult{line: line}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resCh:
		if res.err != nil {
			return nil, res.err
		}
		// If line is empty, recursively read the next line unless context is cancelled
		if len(res.line) == 0 {
			return fr.ReadRawLine(ctx)
		}
		return res.line, nil
	}
}

// ReadMessage parses the next JSON-RPC raw message envelope
func (fr *FramingReader) ReadMessage(ctx context.Context) (*RawMessage, []byte, error) {
	line, err := fr.ReadRawLine(ctx)
	if err != nil {
		return nil, nil, err
	}

	var raw RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, line, fmt.Errorf("json unmarshal failed: %w", err)
	}

	if raw.JSONRPC != JSONRPCVersion {
		return nil, line, fmt.Errorf("unsupported jsonrpc version '%s', expected '%s'", raw.JSONRPC, JSONRPCVersion)
	}

	return &raw, line, nil
}

// FramingWriter thread-safely encodes and writes newline-delimited JSON messages to an io.Writer
type FramingWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

// NewFramingWriter creates a thread-safe FramingWriter
func NewFramingWriter(w io.Writer) *FramingWriter {
	return &FramingWriter{
		writer: w,
	}
}

// WriteMessage serializes any object to JSON and writes it with a trailing newline
func (fw *FramingWriter) WriteMessage(msg any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal json-rpc message: %w", err)
	}

	return fw.WriteRaw(data)
}

// WriteRaw writes raw JSON bytes followed by a newline delimiter atomically
func (fw *FramingWriter) WriteRaw(data []byte) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil
	}

	buf := make([]byte, 0, len(trimmed)+1)
	buf = append(buf, trimmed...)
	buf = append(buf, '\n')

	_, err := fw.writer.Write(buf)
	return err
}
