package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockHealthProvider struct{}

func (m *mockHealthProvider) HealthStatus(ctx context.Context) map[string]any {
	return map[string]any{
		"security": map[string]any{
			"masking":    true,
			"guardrails": true,
			"audit":      true,
		},
		"downstream": "ready",
	}
}

func TestSSEServer_HealthAndReady(t *testing.T) {
	provider := &mockHealthProvider{}
	server := NewSSEServer(":0", nil, provider)

	// Health endpoint test
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var healthResp map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &healthResp)
	require.NoError(t, err)
	assert.Equal(t, "ok", healthResp["status"])
	assert.Equal(t, "v1", healthResp["version"])
	assert.Equal(t, "ready", healthResp["downstream"])

	// Ready endpoint test
	reqReady := httptest.NewRequest(http.MethodGet, "/ready", nil)
	wReady := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(wReady, reqReady)

	assert.Equal(t, http.StatusOK, wReady.Code)
	var readyResp map[string]any
	err = json.Unmarshal(wReady.Body.Bytes(), &readyResp)
	require.NoError(t, err)
	assert.Equal(t, "ready", readyResp["status"])
}

func TestSSEServer_DirectRPC(t *testing.T) {
	handler := func(ctx context.Context, req *RawMessage) (*Response, error) {
		assert.Equal(t, "tools/list", req.Method)
		return NewSuccessResponse(*req.ID, map[string]any{"tools": []string{"query_db"}})
	}

	server := NewSSEServer(":0", handler, nil)

	reqID := NewStringID("123")
	reqPayload := RawMessage{
		JSONRPC: "2.0",
		ID:      &reqID,
		Method:  "tools/list",
	}
	body, err := json.Marshal(reqPayload)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/rpc", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp Response
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, "123", resp.ID.StrVal)
	assert.NotNil(t, resp.Result)
}

func TestSSEServer_SSEStreamingFlow(t *testing.T) {
	handler := func(ctx context.Context, req *RawMessage) (*Response, error) {
		return NewSuccessResponse(*req.ID, map[string]any{"echo": req.Method})
	}

	server := NewSSEServer("127.0.0.1:0", handler, nil)

	// Test SSE handler session registration & message handling
	sessionID := generateSessionID()
	msgCh := make(chan []byte, 10)

	server.mu.Lock()
	server.sessions[sessionID] = msgCh
	server.mu.Unlock()

	reqID := NewStringID("test-456")
	reqPayload := RawMessage{
		JSONRPC: "2.0",
		ID:      &reqID,
		Method:  "ping",
	}
	bodyBytes, err := json.Marshal(reqPayload)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/message?sessionId="+sessionID, bytes.NewReader(bodyBytes))
	rec := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// Check that response was sent to SSE channel
	select {
	case msg := <-msgCh:
		var resp Response
		err := json.Unmarshal(msg, &resp)
		require.NoError(t, err)
		assert.Equal(t, "2.0", resp.JSONRPC)
		assert.Equal(t, "test-456", resp.ID.StrVal)
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for message on SSE channel")
	}

	// Clean up
	server.mu.Lock()
	delete(server.sessions, sessionID)
	server.mu.Unlock()
}
