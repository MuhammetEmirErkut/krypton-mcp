package mcp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestID_StringAndInt(t *testing.T) {
	// String ID
	strID := NewStringID("req-123")
	assert.True(t, strID.IsStr)
	assert.False(t, strID.IsNull)
	assert.Equal(t, "req-123", strID.String())

	data, err := json.Marshal(strID)
	require.NoError(t, err)
	assert.Equal(t, `"req-123"`, string(data))

	var unmarshaledStr RequestID
	require.NoError(t, json.Unmarshal(data, &unmarshaledStr))
	assert.Equal(t, strID, unmarshaledStr)

	// Int ID
	intID := NewIntID(42)
	assert.False(t, intID.IsStr)
	assert.False(t, intID.IsNull)
	assert.Equal(t, "42", intID.String())

	data, err = json.Marshal(intID)
	require.NoError(t, err)
	assert.Equal(t, "42", string(data))

	var unmarshaledInt RequestID
	require.NoError(t, json.Unmarshal(data, &unmarshaledInt))
	assert.Equal(t, intID, unmarshaledInt)

	// Null ID
	nullID := RequestID{IsNull: true}
	assert.Equal(t, "null", nullID.String())
	data, err = json.Marshal(nullID)
	require.NoError(t, err)
	assert.Equal(t, "null", string(data))

	var unmarshaledNull RequestID
	require.NoError(t, json.Unmarshal([]byte("null"), &unmarshaledNull))
	assert.True(t, unmarshaledNull.IsNull)

	// Invalid ID type
	var invalid RequestID
	err = json.Unmarshal([]byte(`{"invalid": true}`), &invalid)
	assert.Error(t, err)
}

func TestRawMessage_Classification(t *testing.T) {
	// Request
	reqRaw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	var reqMsg RawMessage
	require.NoError(t, json.Unmarshal(reqRaw, &reqMsg))
	assert.True(t, reqMsg.IsRequest())
	assert.False(t, reqMsg.IsNotification())
	assert.False(t, reqMsg.IsResponse())

	// Notification
	notifRaw := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	var notifMsg RawMessage
	require.NoError(t, json.Unmarshal(notifRaw, &notifMsg))
	assert.False(t, notifMsg.IsRequest())
	assert.True(t, notifMsg.IsNotification())
	assert.False(t, notifMsg.IsResponse())

	// Response Success
	respRaw := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
	var respMsg RawMessage
	require.NoError(t, json.Unmarshal(respRaw, &respMsg))
	assert.False(t, respMsg.IsRequest())
	assert.False(t, respMsg.IsNotification())
	assert.True(t, respMsg.IsResponse())

	// Response Error
	errRaw := []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`)
	var errMsg RawMessage
	require.NoError(t, json.Unmarshal(errRaw, &errMsg))
	assert.True(t, errMsg.IsResponse())
}

func TestNewRequestAndResponse(t *testing.T) {
	// Request creation
	req, err := NewRequest(NewStringID("req-1"), "tools/call", CallToolParams{
		Name: "calculator",
		Arguments: map[string]interface{}{
			"a": 5,
			"b": 10,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, JSONRPCVersion, req.JSONRPC)
	assert.Equal(t, "tools/call", req.Method)
	assert.Contains(t, string(req.Params), "calculator")

	// Notification creation
	notif, err := NewNotification("notifications/progress", map[string]int{"progress": 50})
	require.NoError(t, err)
	assert.Equal(t, "notifications/progress", notif.Method)
	assert.Contains(t, string(notif.Params), "50")

	// Success Response
	resp, err := NewSuccessResponse(req.ID, CallToolResult{
		Content: []Content{NewTextContent("15")},
	})
	require.NoError(t, err)
	assert.Equal(t, req.ID, resp.ID)
	assert.Contains(t, string(resp.Result), "15")

	// Error Response
	secErr := NewSecurityBlockedError("prompt injection detected in tool argument")
	errResp := NewErrorResponse(req.ID, secErr)
	assert.Equal(t, CodeSecurityBlocked, errResp.Error.Code)
	assert.Contains(t, errResp.Error.Message, "prompt injection detected")
	assert.Contains(t, errResp.Error.Error(), "jsonrpc error:")
}

func TestStandardRPCErrors(t *testing.T) {
	assert.Equal(t, CodeParseError, NewParseError("").Code)
	assert.Equal(t, CodeInvalidRequest, NewInvalidRequestError("").Code)
	assert.Equal(t, CodeMethodNotFound, NewMethodNotFoundError("unknownMethod").Code)
	assert.Equal(t, CodeInvalidParams, NewInvalidParamsError("").Code)
	assert.Equal(t, CodeInternalError, NewInternalError("").Code)

	custom := NewRPCError(-32050, "custom error", map[string]string{"detail": "more info"})
	assert.Equal(t, -32050, custom.Code)
	assert.Contains(t, string(custom.Data), "more info")
}
