package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/krypton-mcp/krypton/internal/config"
	"github.com/krypton-mcp/krypton/pkg/mcp"
)

// RequestInterceptor inspects or modifies an inbound message from the client.
// If intercepted is true, the returned response is sent directly back to the client
// without forwarding the request to the downstream server.
type RequestInterceptor func(ctx context.Context, raw *mcp.RawMessage) (resp *mcp.Response, intercepted bool, err error)

// ResponseInterceptor inspects or modifies an outbound message from the downstream server
// before it reaches the client (e.g. for PII masking or audit signing).
type ResponseInterceptor func(ctx context.Context, raw *mcp.RawMessage) (modified *mcp.RawMessage, err error)

// GatewayProxy bridges an AI Client with a Downstream MCP Server through security filters
type GatewayProxy struct {
	cfg        *config.Config
	supervisor *ProcessSupervisor

	clientReader     *mcp.FramingReader
	clientWriter     *mcp.FramingWriter
	downstreamReader *mcp.FramingReader
	downstreamWriter *mcp.FramingWriter

	reqInterceptors  []RequestInterceptor
	respInterceptors []ResponseInterceptor

	mu     sync.Mutex
	closed bool
}

// GatewayStreams encapsulates the IO streams for both client and downstream
type GatewayStreams struct {
	ClientIn      io.Reader
	ClientOut     io.Writer
	DownstreamIn  io.Reader
	DownstreamOut io.Writer
}

// NewGatewayProxy creates a GatewayProxy instance with explicit streams (useful for testing and stdio)
func NewGatewayProxy(cfg *config.Config, streams GatewayStreams) *GatewayProxy {
	return &GatewayProxy{
		cfg:              cfg,
		clientReader:     mcp.NewFramingReader(streams.ClientIn),
		clientWriter:     mcp.NewFramingWriter(streams.ClientOut),
		downstreamReader: mcp.NewFramingReader(streams.DownstreamIn),
		downstreamWriter: mcp.NewFramingWriter(streams.DownstreamOut),
		reqInterceptors:  make([]RequestInterceptor, 0),
		respInterceptors: make([]ResponseInterceptor, 0),
	}
}

// NewSubprocessGatewayProxy creates a GatewayProxy that spawns and manages a downstream process
func NewSubprocessGatewayProxy(cfg *config.Config, clientIn io.Reader, clientOut io.Writer) *GatewayProxy {
	sup := NewProcessSupervisor(
		cfg.Downstream.Command,
		cfg.Downstream.Args,
		cfg.Downstream.Env,
		cfg.Downstream.WorkingDir,
	)

	return &GatewayProxy{
		cfg:              cfg,
		supervisor:       sup,
		clientReader:     mcp.NewFramingReader(clientIn),
		clientWriter:     mcp.NewFramingWriter(clientOut),
		reqInterceptors:  make([]RequestInterceptor, 0),
		respInterceptors: make([]ResponseInterceptor, 0),
	}
}

// AddRequestInterceptor registers an interceptor for incoming client requests
func (p *GatewayProxy) AddRequestInterceptor(interceptor RequestInterceptor) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reqInterceptors = append(p.reqInterceptors, interceptor)
}

// AddResponseInterceptor registers an interceptor for downstream responses
func (p *GatewayProxy) AddResponseInterceptor(interceptor ResponseInterceptor) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.respInterceptors = append(p.respInterceptors, interceptor)
}

// Start launches the downstream process (if configured) and starts bidirectional proxying
func (p *GatewayProxy) Start(ctx context.Context) error {
	if p.supervisor != nil {
		dsIn, dsOut, _, err := p.supervisor.Start(ctx)
		if err != nil {
			return fmt.Errorf("failed to start downstream server: %w", err)
		}
		defer func() {
			_ = p.supervisor.Stop()
		}()

		p.downstreamWriter = mcp.NewFramingWriter(dsIn)
		p.downstreamReader = mcp.NewFramingReader(dsOut)
	}

	if p.downstreamReader == nil || p.downstreamWriter == nil {
		return errors.New("downstream reader and writer must be initialized")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)

	// Goroutine 1: Client -> Krypton -> Downstream
	go func() {
		errCh <- p.forwardClientToDownstream(ctx)
	}()

	// Goroutine 2: Downstream -> Krypton -> Client
	go func() {
		errCh <- p.forwardDownstreamToClient(ctx)
	}()

	// Wait for any loop to finish or error
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	}
}

func (p *GatewayProxy) forwardClientToDownstream(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		raw, rawBytes, err := p.clientReader.ReadMessage(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return err
			}
			// If JSON unmarshal failed, return JSON-RPC ParseError to client
			parseErr := mcp.NewErrorResponse(mcp.RequestID{IsNull: true}, mcp.NewParseError(err.Error()))
			_ = p.clientWriter.WriteMessage(parseErr)
			continue
		}

		// Apply request interceptors
		p.mu.Lock()
		interceptors := make([]RequestInterceptor, len(p.reqInterceptors))
		copy(interceptors, p.reqInterceptors)
		p.mu.Unlock()

		intercepted := false
		var interceptResp *mcp.Response

		for _, interceptor := range interceptors {
			resp, shouldIntercept, err := interceptor(ctx, raw)
			if err != nil {
				// Interceptor generated error
				if raw.ID != nil {
					errResp := mcp.NewErrorResponse(*raw.ID, mcp.NewInternalError(err.Error()))
					_ = p.clientWriter.WriteMessage(errResp)
				}
				intercepted = true
				break
			}
			if shouldIntercept {
				interceptResp = resp
				intercepted = true
				break
			}
		}

		if intercepted {
			if interceptResp != nil {
				if err := p.clientWriter.WriteMessage(interceptResp); err != nil {
					return fmt.Errorf("failed to write intercepted response: %w", err)
				}
			}
			continue
		}

		// Forward to downstream
		// If raw was modified in place by interceptors, re-marshal; otherwise use fast rawBytes
		if err := p.downstreamWriter.WriteMessage(raw); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return err
			}
			_ = rawBytes // keep reference
			return fmt.Errorf("failed to forward message to downstream: %w", err)
		}
	}
}

func (p *GatewayProxy) forwardDownstreamToClient(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		raw, _, err := p.downstreamReader.ReadMessage(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return err
			}
			return fmt.Errorf("error reading from downstream server: %w", err)
		}

		// Apply response interceptors
		p.mu.Lock()
		interceptors := make([]ResponseInterceptor, len(p.respInterceptors))
		copy(interceptors, p.respInterceptors)
		p.mu.Unlock()

		currentMsg := raw
		for _, interceptor := range interceptors {
			mod, err := interceptor(ctx, currentMsg)
			if err != nil {
				// If interceptor fails, log and continue with unmodified message
				break
			}
			if mod != nil {
				currentMsg = mod
			}
		}

		// Write to client
		var outMessage any
		if currentMsg.IsResponse() {
			if currentMsg.Error != nil {
				outMessage = mcp.NewErrorResponse(*currentMsg.ID, currentMsg.Error)
			} else {
				outMessage = &mcp.Response{
					JSONRPC: currentMsg.JSONRPC,
					ID:      *currentMsg.ID,
					Result:  currentMsg.Result,
				}
			}
		} else if currentMsg.IsNotification() {
			outMessage = &mcp.Notification{
				JSONRPC: currentMsg.JSONRPC,
				Method:  currentMsg.Method,
				Params:  currentMsg.Params,
			}
		} else {
			outMessage = currentMsg
		}

		data, err := json.Marshal(outMessage)
		if err != nil {
			return fmt.Errorf("failed to marshal downstream response: %w", err)
		}

		if err := p.clientWriter.WriteRaw(data); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return err
			}
			return fmt.Errorf("failed to write response to client: %w", err)
		}
	}
}
