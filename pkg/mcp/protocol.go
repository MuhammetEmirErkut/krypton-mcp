package mcp

import (
	"encoding/json"
	"fmt"
)

// JSONRPCVersion is the standard JSON-RPC protocol version supported by MCP
const JSONRPCVersion = "2.0"

// ProtocolVersion is the MCP specification version supported
const ProtocolVersion = "2024-11-05"

// Standard JSON-RPC 2.0 error codes
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603

	// MCP Specific error codes
	CodeConnectionClosed = -32000
	CodeSecurityBlocked  = -32001
)

// Standard MCP method names
const (
	MethodInitialize             = "initialize"
	MethodInitialized            = "notifications/initialized"
	MethodPing                   = "ping"
	MethodToolsList              = "tools/list"
	MethodToolsCall              = "tools/call"
	MethodResourcesList          = "resources/list"
	MethodResourcesRead          = "resources/read"
	MethodPromptsList            = "prompts/list"
	MethodPromptsGet             = "prompts/get"
	MethodLoggingSetLevel        = "logging/setLevel"
	MethodCancelled              = "notifications/cancelled"
	MethodProgress               = "notifications/progress"
)

// RequestID represents a JSON-RPC 2.0 ID which can be a string, an integer, or null
type RequestID struct {
	StrVal string
	IntVal int64
	IsStr  bool
	IsNull bool
}

// NewStringID creates a string RequestID
func NewStringID(id string) RequestID {
	return RequestID{StrVal: id, IsStr: true}
}

// NewIntID creates an integer RequestID
func NewIntID(id int64) RequestID {
	return RequestID{IntVal: id, IsStr: false}
}

// MarshalJSON formats the RequestID for JSON encoding
func (id RequestID) MarshalJSON() ([]byte, error) {
	if id.IsNull {
		return []byte("null"), nil
	}
	if id.IsStr {
		return json.Marshal(id.StrVal)
	}
	return json.Marshal(id.IntVal)
}

// UnmarshalJSON parses a RequestID from raw JSON
func (id *RequestID) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		id.IsNull = true
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		id.StrVal = s
		id.IsStr = true
		id.IsNull = false
		return nil
	}

	var n int64
	if err := json.Unmarshal(data, &n); err == nil {
		id.IntVal = n
		id.IsStr = false
		id.IsNull = false
		return nil
	}

	return fmt.Errorf("invalid json-rpc id type: %s", string(data))
}

// String returns a string representation of the RequestID
func (id RequestID) String() string {
	if id.IsNull {
		return "null"
	}
	if id.IsStr {
		return id.StrVal
	}
	return fmt.Sprintf("%d", id.IntVal)
}

// RawMessage represents a generic JSON-RPC 2.0 message envelope for initial inspection
type RawMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *RequestID      `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// IsRequest returns true if the message is a request (has method and non-null ID)
func (m *RawMessage) IsRequest() bool {
	return m.Method != "" && m.ID != nil && !m.ID.IsNull
}

// IsNotification returns true if the message is a notification (has method and no ID)
func (m *RawMessage) IsNotification() bool {
	return m.Method != "" && (m.ID == nil || m.ID.IsNull)
}

// IsResponse returns true if the message is a response (has ID and result or error, no method)
func (m *RawMessage) IsResponse() bool {
	return m.Method == "" && m.ID != nil
}

// Request represents a JSON-RPC 2.0 Request
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      RequestID       `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// NewRequest creates a new JSON-RPC 2.0 request
func NewRequest(id RequestID, method string, params any) (*Request, error) {
	req := &Request{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Method:  method,
	}
	if params != nil {
		data, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request params: %w", err)
		}
		req.Params = data
	}
	return req, nil
}

// Notification represents a JSON-RPC 2.0 Notification (no ID)
type Notification struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// NewNotification creates a new JSON-RPC 2.0 notification
func NewNotification(method string, params any) (*Notification, error) {
	notif := &Notification{
		JSONRPC: JSONRPCVersion,
		Method:  method,
	}
	if params != nil {
		data, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal notification params: %w", err)
		}
		notif.Params = data
	}
	return notif, nil
}

// Response represents a JSON-RPC 2.0 Successful Response
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      RequestID       `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// NewSuccessResponse creates a successful JSON-RPC 2.0 response
func NewSuccessResponse(id RequestID, result any) (*Response, error) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      id,
	}
	if result != nil {
		data, err := json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response result: %w", err)
		}
		resp.Result = data
	} else {
		resp.Result = json.RawMessage("null")
	}
	return resp, nil
}

// NewErrorResponse creates an error JSON-RPC 2.0 response
func NewErrorResponse(id RequestID, rpcErr *RPCError) *Response {
	return &Response{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error:   rpcErr,
	}
}

// RPCError represents a JSON-RPC 2.0 error object
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Error implements the standard Go error interface
func (e *RPCError) Error() string {
	return fmt.Sprintf("jsonrpc error: code=%d message=%s", e.Code, e.Message)
}

// NewRPCError helper constructor
func NewRPCError(code int, message string, data any) *RPCError {
	rpcErr := &RPCError{
		Code:    code,
		Message: message,
	}
	if data != nil {
		if raw, ok := data.(json.RawMessage); ok {
			rpcErr.Data = raw
		} else if b, err := json.Marshal(data); err == nil {
			rpcErr.Data = b
		}
	}
	return rpcErr
}

// Standard RPC Error Constructors
func NewParseError(detail string) *RPCError {
	if detail == "" {
		detail = "Parse error"
	}
	return &RPCError{Code: CodeParseError, Message: detail}
}

func NewInvalidRequestError(detail string) *RPCError {
	if detail == "" {
		detail = "Invalid Request"
	}
	return &RPCError{Code: CodeInvalidRequest, Message: detail}
}

func NewMethodNotFoundError(method string) *RPCError {
	return &RPCError{Code: CodeMethodNotFound, Message: fmt.Sprintf("Method not found: %s", method)}
}

func NewInvalidParamsError(detail string) *RPCError {
	if detail == "" {
		detail = "Invalid params"
	}
	return &RPCError{Code: CodeInvalidParams, Message: detail}
}

func NewInternalError(detail string) *RPCError {
	if detail == "" {
		detail = "Internal error"
	}
	return &RPCError{Code: CodeInternalError, Message: detail}
}

func NewSecurityBlockedError(reason string) *RPCError {
	return &RPCError{Code: CodeSecurityBlocked, Message: fmt.Sprintf("Krypton Security Gateway: Request blocked - %s", reason)}
}
