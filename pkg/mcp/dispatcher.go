package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// RequestHandlerFunc handles a typed JSON-RPC request and returns a response or error
type RequestHandlerFunc func(ctx context.Context, req *Request) (*Response, error)

// NotificationHandlerFunc handles a one-way notification
type NotificationHandlerFunc func(ctx context.Context, notif *Notification) error

// Middleware intercepts request execution before it reaches the final handler
type Middleware func(ctx context.Context, req *Request, next RequestHandlerFunc) (*Response, error)

// Dispatcher manages method routing, middleware chains, and notification handlers
type Dispatcher struct {
	mu                   sync.RWMutex
	requestHandlers      map[string]RequestHandlerFunc
	notificationHandlers map[string][]NotificationHandlerFunc
	middlewares          []Middleware
}

// NewDispatcher creates an initialized Dispatcher
func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		requestHandlers:      make(map[string]RequestHandlerFunc),
		notificationHandlers: make(map[string][]NotificationHandlerFunc),
		middlewares:          make([]Middleware, 0),
	}
}

// Use appends one or more middlewares to the dispatch pipeline
func (d *Dispatcher) Use(mw ...Middleware) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.middlewares = append(d.middlewares, mw...)
}

// RegisterRequestHandler binds a handler function to an MCP method
func (d *Dispatcher) RegisterRequestHandler(method string, handler RequestHandlerFunc) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.requestHandlers[method] = handler
}

// RegisterNotificationHandler adds a listener for a notification method
func (d *Dispatcher) RegisterNotificationHandler(method string, handler NotificationHandlerFunc) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.notificationHandlers[method] = append(d.notificationHandlers[method], handler)
}

// Dispatch processes an incoming RawMessage through registered handlers and middleware
func (d *Dispatcher) Dispatch(ctx context.Context, raw *RawMessage) (*Response, error) {
	if raw == nil {
		return nil, fmt.Errorf("cannot dispatch nil message")
	}

	if raw.IsRequest() {
		return d.dispatchRequest(ctx, raw)
	}

	if raw.IsNotification() {
		return nil, d.dispatchNotification(ctx, raw)
	}

	return nil, fmt.Errorf("unsupported message type for dispatch")
}

func (d *Dispatcher) dispatchRequest(ctx context.Context, raw *RawMessage) (*Response, error) {
	req := &Request{
		JSONRPC: raw.JSONRPC,
		ID:      *raw.ID,
		Method:  raw.Method,
		Params:  raw.Params,
	}

	d.mu.RLock()
	handler, exists := d.requestHandlers[req.Method]
	middlewares := make([]Middleware, len(d.middlewares))
	copy(middlewares, d.middlewares)
	d.mu.RUnlock()

	if !exists {
		return NewErrorResponse(req.ID, NewMethodNotFoundError(req.Method)), nil
	}

	// Build middleware chain execution pipeline
	pipeline := handler
	for i := len(middlewares) - 1; i >= 0; i-- {
		currentMW := middlewares[i]
		next := pipeline
		pipeline = func(c context.Context, r *Request) (*Response, error) {
			return currentMW(c, r, next)
		}
	}

	resp, err := pipeline(ctx, req)
	if err != nil {
		var rpcErr *RPCError
		if ok := isRPCError(err, &rpcErr); ok {
			return NewErrorResponse(req.ID, rpcErr), nil
		}
		return NewErrorResponse(req.ID, NewInternalError(err.Error())), nil
	}

	if resp == nil {
		return NewSuccessResponse(req.ID, nil)
	}

	return resp, nil
}

func (d *Dispatcher) dispatchNotification(ctx context.Context, raw *RawMessage) error {
	notif := &Notification{
		JSONRPC: raw.JSONRPC,
		Method:  raw.Method,
		Params:  raw.Params,
	}

	d.mu.RLock()
	handlers, exists := d.notificationHandlers[notif.Method]
	d.mu.RUnlock()

	if !exists || len(handlers) == 0 {
		// Notifications without handlers are safely acknowledged/dropped per JSON-RPC spec
		return nil
	}

	for _, h := range handlers {
		if err := h(ctx, notif); err != nil {
			return err
		}
	}

	return nil
}

func isRPCError(err error, target **RPCError) bool {
	if rpcErr, ok := err.(*RPCError); ok {
		*target = rpcErr
		return true
	}
	return false
}

// BindStandardHandlers attaches default handlers for ping and standard lifecycle
func (d *Dispatcher) BindStandardHandlers(serverName, serverVersion string) {
	d.RegisterRequestHandler(MethodPing, func(ctx context.Context, req *Request) (*Response, error) {
		return NewSuccessResponse(req.ID, map[string]string{"status": "pong"})
	})

	d.RegisterRequestHandler(MethodInitialize, func(ctx context.Context, req *Request) (*Response, error) {
		var params InitializeParams
		if len(req.Params) > 0 {
			_ = json.Unmarshal(req.Params, &params)
		}

		result := InitializeResult{
			ProtocolVersion: "2024-11-05",
			ServerInfo: Implementation{
				Name:    serverName,
				Version: serverVersion,
			},
			Capabilities: ServerCapabilities{
				Tools: &ToolsCapability{
					ListChanged: true,
				},
				Resources: &ResourcesCapability{
					ListChanged: true,
				},
				Prompts: &PromptsCapability{
					ListChanged: true,
				},
			},
		}

		return NewSuccessResponse(req.ID, result)
	})
}
