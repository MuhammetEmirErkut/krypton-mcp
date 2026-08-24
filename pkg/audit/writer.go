package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// LogWriter writes serialized audit events to an append-only sink while maintaining the Merkle Tree
type LogWriter struct {
	mu     sync.Mutex
	tree   *MerkleTree
	writer io.Writer
	closer io.Closer
}

// NewFileWriter creates a persistent append-only JSONL log writer
func NewFileWriter(path string) (*LogWriter, error) {
	if path == "" {
		return nil, fmt.Errorf("audit log file path cannot be empty")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create audit log directory: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}

	return &LogWriter{
		tree:   NewMerkleTree(),
		writer: file,
		closer: file,
	}, nil
}

// NewMemoryWriter creates an in-memory audit log writer (useful for tests and ephemeral sessions)
func NewMemoryWriter() (*LogWriter, *bytes.Buffer) {
	buf := new(bytes.Buffer)
	return &LogWriter{
		tree:   NewMerkleTree(),
		writer: buf,
	}, buf
}

// Tree returns the underlying MerkleTree
func (w *LogWriter) Tree() *MerkleTree {
	return w.tree
}

// WriteEvent computes the leaf hash, appends to the Merkle tree, and writes the JSONL line
func (w *LogWriter) WriteEvent(evt *AuditEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if evt == nil {
		return fmt.Errorf("cannot write nil audit event")
	}

	if _, _, err := w.tree.AppendEvent(evt); err != nil {
		return fmt.Errorf("failed to append event to merkle tree: %w", err)
	}

	data, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("failed to serialize audit event: %w", err)
	}

	if _, err := w.writer.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write audit log entry: %w", err)
	}

	return nil
}

// Close closes the underlying file handle if open
func (w *LogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closer != nil {
		return w.closer.Close()
	}
	return nil
}
