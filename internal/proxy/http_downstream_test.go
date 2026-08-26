package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/krypton-mcp/krypton/internal/config"
	"github.com/krypton-mcp/krypton/pkg/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(req *http.Request) *http.Response

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func TestHTTPDownstreamClient_Forward(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) *http.Response {
		assert.Equal(t, http.MethodPost, req.Method)
		assert.Equal(t, "application/json", req.Header.Get("Content-Type"))

		var raw mcp.RawMessage
		_ = json.NewDecoder(req.Body).Decode(&raw)

		resp := mcp.Response{
			JSONRPC: "2.0",
			ID:      *raw.ID,
			Result:  json.RawMessage(`{"greeting":"hello from downstream"}`),
		}
		data, _ := json.Marshal(resp)

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(data)),
			Header:     make(http.Header),
		}
	})

	client := NewHTTPDownstreamClient("http://mock-downstream/rpc")
	client.SetTransport(rt)

	reqID := mcp.NewStringID("req-1")
	rawReq := &mcp.RawMessage{
		JSONRPC: "2.0",
		ID:      &reqID,
		Method:  "greet",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	respRaw, err := client.Forward(ctx, rawReq)
	require.NoError(t, err)
	require.NotNil(t, respRaw)
	assert.Equal(t, "2.0", respRaw.JSONRPC)
	assert.Equal(t, "req-1", respRaw.ID.StrVal)
	assert.JSONEq(t, `{"greeting":"hello from downstream"}`, string(respRaw.Result))
}

func TestGatewayProxy_HandleClientRequest_HTTPDownstream(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) *http.Response {
		var raw mcp.RawMessage
		_ = json.NewDecoder(req.Body).Decode(&raw)

		resp := mcp.Response{
			JSONRPC: "2.0",
			ID:      *raw.ID,
			Result:  json.RawMessage(`{"content":[{"type":"text","text":"User found with email alice@example.com"}]}`),
		}
		data, _ := json.Marshal(resp)

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(data)),
			Header:     make(http.Header),
		}
	})

	cfg := config.DefaultConfig()
	cfg.Downstream.Transport = "http"
	cfg.Downstream.URL = "http://mock-downstream/rpc"
	cfg.Security.MaskingEnabled = true
	cfg.Masking.Mode = "tokenize"

	gw := NewSubprocessGatewayProxy(cfg, nil, nil)
	require.NotNil(t, gw)

	httpDs := NewHTTPDownstreamClient(cfg.Downstream.URL)
	httpDs.SetTransport(rt)
	gw.SetHTTPDownstream(httpDs)

	reqID := mcp.NewStringID("call-1")
	req := &mcp.RawMessage{
		JSONRPC: "2.0",
		ID:      &reqID,
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"get_user","arguments":{}}`),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := gw.HandleClientRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "call-1", resp.ID.StrVal)

	// Result should be masked
	assert.Contains(t, string(resp.Result), "EMAIL_REF_")
	assert.NotContains(t, string(resp.Result), "alice@example.com")
}
