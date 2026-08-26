package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/krypton-mcp/krypton/pkg/mcp"
)

// HTTPDownstreamClient manages JSON-RPC communication with a remote HTTP MCP server
type HTTPDownstreamClient struct {
	url        string
	httpClient *http.Client
}

// NewHTTPDownstreamClient creates a new client for a remote MCP server
func NewHTTPDownstreamClient(url string) *HTTPDownstreamClient {
	return &HTTPDownstreamClient{
		url: url,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// SetTransport allows injecting a custom http.RoundTripper (useful for in-memory testing and mTLS)
func (c *HTTPDownstreamClient) SetTransport(rt http.RoundTripper) {
	if c.httpClient != nil {
		c.httpClient.Transport = rt
	}
}

// Forward sends a RawMessage to the downstream HTTP server and unmarshals the response
func (c *HTTPDownstreamClient) Forward(ctx context.Context, raw *mcp.RawMessage) (*mcp.RawMessage, error) {
	reqBytes, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal downstream request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create downstream http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "KryptonMCP-Gateway/0.1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downstream http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("downstream server returned error HTTP status %d: %s", resp.StatusCode, string(respBody))
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read downstream response body: %w", err)
	}

	if len(bytes.TrimSpace(respBytes)) == 0 {
		return nil, nil
	}

	var respMsg mcp.RawMessage
	if err := json.Unmarshal(respBytes, &respMsg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal downstream json-rpc response: %w", err)
	}

	return &respMsg, nil
}
