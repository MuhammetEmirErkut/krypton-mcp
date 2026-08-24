package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/krypton-mcp/krypton/internal/config"
	"github.com/krypton-mcp/krypton/pkg/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGatewayProxy_PassThrough(t *testing.T) {
	clientInPipeR, clientInPipeW := io.Pipe()
	clientOutPipeR, clientOutPipeW := io.Pipe()
	downstreamInPipeR, downstreamInPipeW := io.Pipe()
	downstreamOutPipeR, downstreamOutPipeW := io.Pipe()

	cfg := config.DefaultConfig()

	proxy := NewGatewayProxy(cfg, GatewayStreams{
		ClientIn:      clientInPipeR,
		ClientOut:     clientOutPipeW,
		DownstreamIn:  downstreamOutPipeR,
		DownstreamOut: downstreamInPipeW,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	proxyErrCh := make(chan error, 1)
	go func() {
		proxyErrCh <- proxy.Start(ctx)
	}()

	clientWriter := mcp.NewFramingWriter(clientInPipeW)
	clientReader := mcp.NewFramingReader(clientOutPipeR)
	downstreamReader := mcp.NewFramingReader(downstreamInPipeR)
	downstreamWriter := mcp.NewFramingWriter(downstreamOutPipeW)

	// 1. Client sends "tools/list" request
	req, err := mcp.NewRequest(mcp.NewIntID(1), "tools/list", nil)
	require.NoError(t, err)
	require.NoError(t, clientWriter.WriteMessage(req))

	// 2. Downstream receives "tools/list" request through proxy
	dsMsg, _, err := downstreamReader.ReadMessage(ctx)
	require.NoError(t, err)
	assert.Equal(t, "tools/list", dsMsg.Method)
	assert.Equal(t, int64(1), dsMsg.ID.IntVal)

	// 3. Downstream replies with tool list
	dsResp, err := mcp.NewSuccessResponse(*dsMsg.ID, mcp.ListToolsResult{
		Tools: []mcp.Tool{
			{Name: "execute_sql", Description: "PostgreSQL query tool"},
		},
	})
	require.NoError(t, err)
	require.NoError(t, downstreamWriter.WriteMessage(dsResp))

	// 4. Client receives tool list through proxy
	clientRespMsg, _, err := clientReader.ReadMessage(ctx)
	require.NoError(t, err)
	assert.True(t, clientRespMsg.IsResponse())
	assert.Equal(t, int64(1), clientRespMsg.ID.IntVal)
	assert.Contains(t, string(clientRespMsg.Result), "execute_sql")

	// 5. Downstream sends notification to client
	notif, err := mcp.NewNotification("notifications/progress", map[string]int{"percent": 100})
	require.NoError(t, err)
	require.NoError(t, downstreamWriter.WriteMessage(notif))

	clientNotifMsg, _, err := clientReader.ReadMessage(ctx)
	require.NoError(t, err)
	assert.True(t, clientNotifMsg.IsNotification())
	assert.Equal(t, "notifications/progress", clientNotifMsg.Method)

	cancel()
	_ = clientInPipeW.Close()
	_ = downstreamOutPipeW.Close()
}

func TestGatewayProxy_RequestInterception(t *testing.T) {
	clientInPipeR, clientInPipeW := io.Pipe()
	clientOutPipeR, clientOutPipeW := io.Pipe()
	downstreamInPipeR, downstreamInPipeW := io.Pipe()
	downstreamOutPipeR, _ := io.Pipe()

	cfg := config.DefaultConfig()

	proxy := NewGatewayProxy(cfg, GatewayStreams{
		ClientIn:      clientInPipeR,
		ClientOut:     clientOutPipeW,
		DownstreamIn:  downstreamOutPipeR,
		DownstreamOut: downstreamInPipeW,
	})

	// Add interceptor that blocks any request containing "drop_database"
	proxy.AddRequestInterceptor(func(ctx context.Context, raw *mcp.RawMessage) (*mcp.Response, bool, error) {
		if raw.Method == "tools/call" && raw.Params != nil {
			var params mcp.CallToolParams
			if err := json.Unmarshal(raw.Params, &params); err == nil {
				if params.Name == "drop_database" {
					return mcp.NewErrorResponse(*raw.ID, mcp.NewSecurityBlockedError("tool 'drop_database' is forbidden by security policy")), true, nil
				}
			}
		}
		return nil, false, nil
	})

	// Interceptor that throws an error
	proxy.AddRequestInterceptor(func(ctx context.Context, raw *mcp.RawMessage) (*mcp.Response, bool, error) {
		if raw.Method == "error_trigger" {
			return nil, false, errors.New("interceptor failure")
		}
		return nil, false, nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go func() {
		_ = proxy.Start(ctx)
	}()

	clientWriter := mcp.NewFramingWriter(clientInPipeW)
	clientReader := mcp.NewFramingReader(clientOutPipeR)

	// 1. Send forbidden tool call
	req, err := mcp.NewRequest(mcp.NewIntID(99), "tools/call", mcp.CallToolParams{
		Name: "drop_database",
	})
	require.NoError(t, err)
	require.NoError(t, clientWriter.WriteMessage(req))

	// Client should immediately receive blocked error without downstream involvement
	resp, _, err := clientReader.ReadMessage(ctx)
	require.NoError(t, err)
	assert.True(t, resp.IsResponse())
	assert.Equal(t, int64(99), resp.ID.IntVal)
	require.NotNil(t, resp.Error)
	assert.Equal(t, mcp.CodeSecurityBlocked, resp.Error.Code)
	assert.Contains(t, resp.Error.Message, "forbidden by security policy")

	// 2. Send error trigger request
	errReq, err := mcp.NewRequest(mcp.NewIntID(100), "error_trigger", nil)
	require.NoError(t, err)
	require.NoError(t, clientWriter.WriteMessage(errReq))

	errResp, _, err := clientReader.ReadMessage(ctx)
	require.NoError(t, err)
	require.NotNil(t, errResp.Error)
	assert.Equal(t, mcp.CodeInternalError, errResp.Error.Code)

	// Verify downstream reader timed out (never received any message)
	downstreamReader := mcp.NewFramingReader(downstreamInPipeR)
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer probeCancel()
	_, _, err = downstreamReader.ReadMessage(probeCtx)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	cancel()
}

func TestGatewayProxy_ResponseInterception(t *testing.T) {
	clientInPipeR, clientInPipeW := io.Pipe()
	clientOutPipeR, clientOutPipeW := io.Pipe()
	downstreamInPipeR, downstreamInPipeW := io.Pipe()
	downstreamOutPipeR, downstreamOutPipeW := io.Pipe()

	cfg := config.DefaultConfig()

	proxy := NewGatewayProxy(cfg, GatewayStreams{
		ClientIn:      clientInPipeR,
		ClientOut:     clientOutPipeW,
		DownstreamIn:  downstreamOutPipeR,
		DownstreamOut: downstreamInPipeW,
	})

	// Add response interceptor that redacts sensitive text
	proxy.AddResponseInterceptor(func(ctx context.Context, raw *mcp.RawMessage) (*mcp.RawMessage, error) {
		if raw.IsResponse() && raw.Result != nil {
			maskedResult := `{"content":[{"type":"text","text":"[PII_MASKED]"}]}`
			raw.Result = json.RawMessage(maskedResult)
		}
		return raw, nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go func() {
		_ = proxy.Start(ctx)
	}()

	clientWriter := mcp.NewFramingWriter(clientInPipeW)
	clientReader := mcp.NewFramingReader(clientOutPipeR)
	downstreamReader := mcp.NewFramingReader(downstreamInPipeR)
	downstreamWriter := mcp.NewFramingWriter(downstreamOutPipeW)

	req, _ := mcp.NewRequest(mcp.NewIntID(1), "tools/call", mcp.CallToolParams{Name: "get_user"})
	_ = clientWriter.WriteMessage(req)

	dsMsg, _, _ := downstreamReader.ReadMessage(ctx)
	dsResp, _ := mcp.NewSuccessResponse(*dsMsg.ID, mcp.CallToolResult{
		Content: []mcp.Content{mcp.NewTextContent("john.doe@enterprise.com")},
	})
	_ = downstreamWriter.WriteMessage(dsResp)

	clientMsg, _, err := clientReader.ReadMessage(ctx)
	require.NoError(t, err)
	assert.Contains(t, string(clientMsg.Result), "[PII_MASKED]")
	assert.NotContains(t, string(clientMsg.Result), "john.doe@enterprise.com")

	cancel()
}

func TestGatewayProxy_InvalidJSONFromClient(t *testing.T) {
	clientInPipeR, clientInPipeW := io.Pipe()
	clientOutPipeR, clientOutPipeW := io.Pipe()
	downstreamInPipeR, downstreamInPipeW := io.Pipe()
	downstreamOutPipeR, _ := io.Pipe()

	cfg := config.DefaultConfig()

	proxy := NewGatewayProxy(cfg, GatewayStreams{
		ClientIn:      clientInPipeR,
		ClientOut:     clientOutPipeW,
		DownstreamIn:  downstreamOutPipeR,
		DownstreamOut: downstreamInPipeW,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go func() {
		_ = proxy.Start(ctx)
	}()

	clientReader := mcp.NewFramingReader(clientOutPipeR)

	// Write malformed JSON line
	_, _ = clientInPipeW.Write([]byte("{invalid-json-line\n"))

	resp, _, err := clientReader.ReadMessage(ctx)
	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Equal(t, mcp.CodeParseError, resp.Error.Code)

	_ = downstreamInPipeR // suppress unused warning
	_ = downstreamInPipeW
	cancel()
}

func TestGatewayProxy_SubprocessLifecycle(t *testing.T) {
	clientInPipeR, clientInPipeW := io.Pipe()
	clientOutPipeR, clientOutPipeW := io.Pipe()

	cfg := config.DefaultConfig()
	cfg.Downstream.Command = "cat" // acts as downstream echo server

	proxy := NewSubprocessGatewayProxy(cfg, clientInPipeR, clientOutPipeW)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go func() {
		_ = proxy.Start(ctx)
	}()

	clientWriter := mcp.NewFramingWriter(clientInPipeW)
	clientReader := mcp.NewFramingReader(clientOutPipeR)

	// Send ping through cat subprocess echo
	req, _ := mcp.NewRequest(mcp.NewIntID(123), "ping", nil)
	require.NoError(t, clientWriter.WriteMessage(req))

	echoedMsg, _, err := clientReader.ReadMessage(ctx)
	require.NoError(t, err)
	assert.Equal(t, "ping", echoedMsg.Method)
	assert.Equal(t, int64(123), echoedMsg.ID.IntVal)

	cancel()
}
