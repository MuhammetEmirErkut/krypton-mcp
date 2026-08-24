package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDispatcher_RequestSuccess(t *testing.T) {
	dispatcher := NewDispatcher()

	dispatcher.RegisterRequestHandler("tools/list", func(ctx context.Context, req *Request) (*Response, error) {
		return NewSuccessResponse(req.ID, ListToolsResult{
			Tools: []Tool{
				{
					Name:        "query_db",
					Description: "Runs a read-only SQL query",
				},
			},
		})
	})

	reqRaw := &RawMessage{
		JSONRPC: JSONRPCVersion,
		ID:      &RequestID{IntVal: 1, IsStr: false},
		Method:  "tools/list",
	}

	resp, err := dispatcher.Dispatch(context.Background(), reqRaw)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)
	assert.Contains(t, string(resp.Result), "query_db")
}

func TestDispatcher_MethodNotFound(t *testing.T) {
	dispatcher := NewDispatcher()

	reqRaw := &RawMessage{
		JSONRPC: JSONRPCVersion,
		ID:      &RequestID{StrVal: "req-404", IsStr: true},
		Method:  "non_existent_method",
	}

	resp, err := dispatcher.Dispatch(context.Background(), reqRaw)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Equal(t, CodeMethodNotFound, resp.Error.Code)
	assert.Contains(t, resp.Error.Message, "non_existent_method")
}

func TestDispatcher_HandlerErrors(t *testing.T) {
	dispatcher := NewDispatcher()

	// Handler returning generic Go error -> should map to InternalError (-32603)
	dispatcher.RegisterRequestHandler("fail_generic", func(ctx context.Context, req *Request) (*Response, error) {
		return nil, errors.New("database connection failed")
	})

	// Handler returning typed RPCError -> should preserve exact code
	dispatcher.RegisterRequestHandler("fail_custom", func(ctx context.Context, req *Request) (*Response, error) {
		return nil, NewRPCError(CodeInvalidParams, "missing required field 'query'", nil)
	})

	// 1. Generic
	resp1, err := dispatcher.Dispatch(context.Background(), &RawMessage{
		JSONRPC: JSONRPCVersion,
		ID:      &RequestID{IntVal: 1},
		Method:  "fail_generic",
	})
	require.NoError(t, err)
	require.NotNil(t, resp1.Error)
	assert.Equal(t, CodeInternalError, resp1.Error.Code)
	assert.Contains(t, resp1.Error.Message, "database connection failed")

	// 2. Typed RPCError
	resp2, err := dispatcher.Dispatch(context.Background(), &RawMessage{
		JSONRPC: JSONRPCVersion,
		ID:      &RequestID{IntVal: 2},
		Method:  "fail_custom",
	})
	require.NoError(t, err)
	require.NotNil(t, resp2.Error)
	assert.Equal(t, CodeInvalidParams, resp2.Error.Code)
	assert.Contains(t, resp2.Error.Message, "missing required field 'query'")
}

func TestDispatcher_MiddlewareChain(t *testing.T) {
	dispatcher := NewDispatcher()
	var executionOrder []string

	// Middleware 1: Logging / Tracking
	dispatcher.Use(func(ctx context.Context, req *Request, next RequestHandlerFunc) (*Response, error) {
		executionOrder = append(executionOrder, "mw1_start")
		resp, err := next(ctx, req)
		executionOrder = append(executionOrder, "mw1_end")
		return resp, err
	})

	// Middleware 2: Guardrail check
	dispatcher.Use(func(ctx context.Context, req *Request, next RequestHandlerFunc) (*Response, error) {
		executionOrder = append(executionOrder, "mw2_start")
		resp, err := next(ctx, req)
		executionOrder = append(executionOrder, "mw2_end")
		return resp, err
	})

	dispatcher.RegisterRequestHandler("test_method", func(ctx context.Context, req *Request) (*Response, error) {
		executionOrder = append(executionOrder, "handler")
		return NewSuccessResponse(req.ID, map[string]string{"result": "ok"})
	})

	resp, err := dispatcher.Dispatch(context.Background(), &RawMessage{
		JSONRPC: JSONRPCVersion,
		ID:      &RequestID{IntVal: 10},
		Method:  "test_method",
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, []string{
		"mw1_start",
		"mw2_start",
		"handler",
		"mw2_end",
		"mw1_end",
	}, executionOrder)
}

func TestDispatcher_MiddlewareShortCircuit(t *testing.T) {
	dispatcher := NewDispatcher()

	// Security middleware that blocks requests containing "malicious"
	dispatcher.Use(func(ctx context.Context, req *Request, next RequestHandlerFunc) (*Response, error) {
		if string(req.Params) == `"malicious"` {
			return nil, NewSecurityBlockedError("injection payload detected")
		}
		return next(ctx, req)
	})

	handlerCalled := false
	dispatcher.RegisterRequestHandler("exec", func(ctx context.Context, req *Request) (*Response, error) {
		handlerCalled = true
		return NewSuccessResponse(req.ID, "success")
	})

	// Blocked request
	resp, err := dispatcher.Dispatch(context.Background(), &RawMessage{
		JSONRPC: JSONRPCVersion,
		ID:      &RequestID{IntVal: 1},
		Method:  "exec",
		Params:  json.RawMessage(`"malicious"`),
	})
	require.NoError(t, err)
	assert.False(t, handlerCalled)
	require.NotNil(t, resp.Error)
	assert.Equal(t, CodeSecurityBlocked, resp.Error.Code)

	// Allowed request
	respAllowed, err := dispatcher.Dispatch(context.Background(), &RawMessage{
		JSONRPC: JSONRPCVersion,
		ID:      &RequestID{IntVal: 2},
		Method:  "exec",
		Params:  json.RawMessage(`"clean"`),
	})
	require.NoError(t, err)
	assert.True(t, handlerCalled)
	assert.Nil(t, respAllowed.Error)
}

func TestDispatcher_Notifications(t *testing.T) {
	dispatcher := NewDispatcher()
	var notifReceived string

	dispatcher.RegisterNotificationHandler("notifications/initialized", func(ctx context.Context, notif *Notification) error {
		notifReceived = notif.Method
		return nil
	})

	// 1. Matching handler
	err := dispatcher.dispatchNotification(context.Background(), &RawMessage{
		JSONRPC: JSONRPCVersion,
		Method:  "notifications/initialized",
	})
	require.NoError(t, err)
	assert.Equal(t, "notifications/initialized", notifReceived)

	// 2. Unhandled notification drops safely
	err = dispatcher.dispatchNotification(context.Background(), &RawMessage{
		JSONRPC: JSONRPCVersion,
		Method:  "unhandled/notification",
	})
	require.NoError(t, err)
}

func TestDispatcher_BindStandardHandlers(t *testing.T) {
	dispatcher := NewDispatcher()
	dispatcher.BindStandardHandlers("KryptonGateway", "0.1.0")

	// 1. Ping
	respPing, err := dispatcher.Dispatch(context.Background(), &RawMessage{
		JSONRPC: JSONRPCVersion,
		ID:      &RequestID{IntVal: 1},
		Method:  MethodPing,
	})
	require.NoError(t, err)
	assert.Nil(t, respPing.Error)
	assert.Contains(t, string(respPing.Result), "pong")

	// 2. Initialize
	respInit, err := dispatcher.Dispatch(context.Background(), &RawMessage{
		JSONRPC: JSONRPCVersion,
		ID:      &RequestID{IntVal: 2},
		Method:  MethodInitialize,
	})
	require.NoError(t, err)
	assert.Nil(t, respInit.Error)
	assert.Contains(t, string(respInit.Result), "KryptonGateway")
	assert.Contains(t, string(respInit.Result), "2024-11-05")
}
