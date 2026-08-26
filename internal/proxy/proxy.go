package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/krypton-mcp/krypton/internal/config"
	"github.com/krypton-mcp/krypton/pkg/audit"
	"github.com/krypton-mcp/krypton/pkg/guardrails"
	"github.com/krypton-mcp/krypton/pkg/masker"
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
	cfg            *config.Config
	supervisor     *ProcessSupervisor
	httpDownstream *HTTPDownstreamClient

	clientReader     *mcp.FramingReader
	clientWriter     *mcp.FramingWriter
	downstreamReader *mcp.FramingReader
	downstreamWriter *mcp.FramingWriter

	reqInterceptors  []RequestInterceptor
	respInterceptors []ResponseInterceptor

	tokenizer         *masker.Tokenizer
	injectionDetector *guardrails.InjectionDetector
	policyEngine      *guardrails.PolicyEngine
	auditWriter       *audit.LogWriter

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
	proxy := &GatewayProxy{
		cfg:              cfg,
		clientReader:     mcp.NewFramingReader(streams.ClientIn),
		clientWriter:     mcp.NewFramingWriter(streams.ClientOut),
		downstreamReader: mcp.NewFramingReader(streams.DownstreamIn),
		downstreamWriter: mcp.NewFramingWriter(streams.DownstreamOut),
		reqInterceptors:  make([]RequestInterceptor, 0),
		respInterceptors: make([]ResponseInterceptor, 0),
	}

	if cfg != nil && cfg.Downstream.URL != "" {
		proxy.httpDownstream = NewHTTPDownstreamClient(cfg.Downstream.URL)
	}

	proxy.initSecurityPipelines()
	return proxy
}

// NewSubprocessGatewayProxy creates a GatewayProxy that spawns and manages a downstream process or remote HTTP downstream
func NewSubprocessGatewayProxy(cfg *config.Config, clientIn io.Reader, clientOut io.Writer) *GatewayProxy {
	var sup *ProcessSupervisor
	var httpDs *HTTPDownstreamClient

	if cfg.Downstream.URL != "" {
		httpDs = NewHTTPDownstreamClient(cfg.Downstream.URL)
	} else if cfg.Downstream.Command != "" {
		sup = NewProcessSupervisor(
			cfg.Downstream.Command,
			cfg.Downstream.Args,
			cfg.Downstream.Env,
			cfg.Downstream.WorkingDir,
		)
	}

	proxy := &GatewayProxy{
		cfg:              cfg,
		supervisor:       sup,
		httpDownstream:   httpDs,
		clientReader:     mcp.NewFramingReader(clientIn),
		clientWriter:     mcp.NewFramingWriter(clientOut),
		reqInterceptors:  make([]RequestInterceptor, 0),
		respInterceptors: make([]ResponseInterceptor, 0),
	}

	proxy.initSecurityPipelines()
	return proxy
}

func (p *GatewayProxy) initSecurityPipelines() {
	if p.cfg == nil {
		return
	}

	// 1. Initialize Audit Logging & Merkle Ledger
	if p.cfg.Security.AuditEnabled && p.cfg.Audit.LogPath != "" {
		writer, err := audit.NewFileWriter(p.cfg.Audit.LogPath)
		if err == nil {
			p.auditWriter = writer
			p.AddRequestInterceptor(func(ctx context.Context, raw *mcp.RawMessage) (*mcp.Response, bool, error) {
				evtType := audit.EventMCPRequest
				if raw.Method == mcp.MethodToolsCall {
					evtType = audit.EventToolExecution
				}
				evt := audit.NewAuditEvent(evtType, "client", raw.Method, raw.Params, nil)
				_ = writer.WriteEvent(evt)
				return nil, false, nil
			})

			p.AddResponseInterceptor(func(ctx context.Context, raw *mcp.RawMessage) (*mcp.RawMessage, error) {
				evt := audit.NewAuditEvent(audit.EventMCPResponse, "downstream", "", raw.Result, nil)
				_ = writer.WriteEvent(evt)
				return raw, nil
			})
		}
	}

	// 2. Initialize Guardrails Interceptor (Injection defense + RBAC + Size limits)
	if p.cfg.Security.GuardrailsEnabled {
		p.injectionDetector = guardrails.NewInjectionDetector()
		if p.policyEngine == nil {
			polCfg := p.cfg.Guardrails.ToPolicyConfig()
			pe, _ := guardrails.NewPolicyEngine(polCfg)
			p.policyEngine = pe
		}

		p.AddRequestInterceptor(func(ctx context.Context, raw *mcp.RawMessage) (*mcp.Response, bool, error) {
			p.mu.Lock()
			detector := p.injectionDetector
			pe := p.policyEngine
			p.mu.Unlock()
			return guardrails.GuardrailRequestInterceptor(detector, pe, p.cfg.Guardrails.MaxPromptSizeBytes)(ctx, raw)
		})
	}

	// 3. Initialize In-Flight Masking Interceptors (Inbound unmasking + Outbound masking)
	if p.cfg.Security.MaskingEnabled {
		tok, err := masker.NewTokenizer(&p.cfg.Masking, nil)
		if err == nil {
			p.tokenizer = tok
			p.AddRequestInterceptor(func(ctx context.Context, raw *mcp.RawMessage) (*mcp.Response, bool, error) {
				p.mu.Lock()
				t := p.tokenizer
				p.mu.Unlock()
				if t != nil {
					return masker.DetokenizingRequestInterceptor(t)(ctx, raw)
				}
				return nil, false, nil
			})
			p.AddResponseInterceptor(func(ctx context.Context, raw *mcp.RawMessage) (*mcp.RawMessage, error) {
				p.mu.Lock()
				t := p.tokenizer
				p.mu.Unlock()
				if t != nil {
					return masker.MaskingResponseInterceptor(t)(ctx, raw)
				}
				return raw, nil
			})
		}
	}
}

// AttachMasker manually sets a tokenizer and registers its interceptors
func (p *GatewayProxy) AttachMasker(tok *masker.Tokenizer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenizer = tok
}

// AttachPolicyEngine sets the policy engine
func (p *GatewayProxy) AttachPolicyEngine(pe *guardrails.PolicyEngine) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.policyEngine = pe
}

// AttachAuditWriter sets the audit log writer
func (p *GatewayProxy) AttachAuditWriter(w *audit.LogWriter) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.auditWriter = w
}

// SetHTTPDownstream sets the downstream HTTP client
func (p *GatewayProxy) SetHTTPDownstream(c *HTTPDownstreamClient) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.httpDownstream = c
}

// Tokenizer returns the active tokenizer instance
func (p *GatewayProxy) Tokenizer() *masker.Tokenizer {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tokenizer
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

// Start launches the downstream process or connects to remote HTTP downstream and begins proxying
func (p *GatewayProxy) Start(ctx context.Context) error {
	if p.cfg != nil {
		fmt.Fprintf(os.Stderr, "[krypton] Zero-Trust Gateway running (transport: stdio, masking: %t, guardrails: %t, audit: %t)\n",
			p.cfg.Security.MaskingEnabled, p.cfg.Security.GuardrailsEnabled, p.cfg.Security.AuditEnabled)

		if p.httpDownstream != nil {
			fmt.Fprintf(os.Stderr, "[krypton] Downstream target (HTTP): %s\n", p.cfg.Downstream.URL)
			return p.startHTTPDownstreamStdioLoop(ctx)
		}

		if p.supervisor != nil {
			fmt.Fprintf(os.Stderr, "[krypton] Downstream target (Subprocess): %s %v\n", p.cfg.Downstream.Command, p.cfg.Downstream.Args)
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
	} else if p.httpDownstream != nil {
		return p.startHTTPDownstreamStdioLoop(ctx)
	} else if p.supervisor != nil {
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
	defer func() {
		p.mu.Lock()
		if p.auditWriter != nil {
			_ = p.auditWriter.Close()
		}
		p.mu.Unlock()
	}()

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

func (p *GatewayProxy) startHTTPDownstreamStdioLoop(ctx context.Context) error {
	defer func() {
		p.mu.Lock()
		if p.auditWriter != nil {
			_ = p.auditWriter.Close()
		}
		p.mu.Unlock()
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		raw, _, err := p.clientReader.ReadMessage(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				fmt.Fprintf(os.Stderr, "[krypton] Client stdin closed (EOF). Gateway shutting down cleanly.\n")
				return nil
			}
			parseErr := mcp.NewErrorResponse(mcp.RequestID{IsNull: true}, mcp.NewParseError(err.Error()))
			_ = p.clientWriter.WriteMessage(parseErr)
			continue
		}

		resp, err := p.HandleClientRequest(ctx, raw)
		if err != nil {
			if raw.ID != nil {
				resp = mcp.NewErrorResponse(*raw.ID, mcp.NewInternalError(err.Error()))
			}
		}

		if resp != nil {
			if err := p.clientWriter.WriteMessage(resp); err != nil {
				return fmt.Errorf("failed to write response to client: %w", err)
			}
		}
	}
}

// HandleClientRequest runs the complete inbound and outbound security pipeline for a single request
func (p *GatewayProxy) HandleClientRequest(ctx context.Context, raw *mcp.RawMessage) (*mcp.Response, error) {
	// 1. Run request interceptors
	p.mu.Lock()
	interceptors := make([]RequestInterceptor, len(p.reqInterceptors))
	copy(interceptors, p.reqInterceptors)
	p.mu.Unlock()

	for _, interceptor := range interceptors {
		resp, shouldIntercept, err := interceptor(ctx, raw)
		if err != nil {
			if raw.ID != nil {
				return mcp.NewErrorResponse(*raw.ID, mcp.NewInternalError(err.Error())), nil
			}
			return nil, err
		}
		if shouldIntercept {
			return resp, nil
		}
	}

	// 2. Forward to downstream
	var downstreamRaw *mcp.RawMessage
	if p.httpDownstream != nil {
		var err error
		downstreamRaw, err = p.httpDownstream.Forward(ctx, raw)
		if err != nil {
			if raw.ID != nil {
				return mcp.NewErrorResponse(*raw.ID, mcp.NewInternalError(err.Error())), nil
			}
			return nil, err
		}
	} else if p.downstreamWriter != nil && p.downstreamReader != nil {
		if err := p.downstreamWriter.WriteMessage(raw); err != nil {
			return nil, fmt.Errorf("failed to write to downstream process: %w", err)
		}
		var err error
		downstreamRaw, _, err = p.downstreamReader.ReadMessage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to read from downstream process: %w", err)
		}
	} else {
		return nil, errors.New("no downstream transport available")
	}

	if downstreamRaw == nil {
		return nil, nil
	}

	// 3. Run response interceptors
	p.mu.Lock()
	respInterceptors := make([]ResponseInterceptor, len(p.respInterceptors))
	copy(respInterceptors, p.respInterceptors)
	p.mu.Unlock()

	currentMsg := downstreamRaw
	for _, interceptor := range respInterceptors {
		mod, err := interceptor(ctx, currentMsg)
		if err != nil {
			break
		}
		if mod != nil {
			currentMsg = mod
		}
	}

	// 4. Convert to Response
	if currentMsg.IsResponse() {
		if currentMsg.Error != nil {
			return mcp.NewErrorResponse(*currentMsg.ID, currentMsg.Error), nil
		}
		return &mcp.Response{
			JSONRPC: currentMsg.JSONRPC,
			ID:      *currentMsg.ID,
			Result:  currentMsg.Result,
		}, nil
	}

	return nil, nil
}

// HealthStatus returns health and readiness metadata for health checks
func (p *GatewayProxy) HealthStatus(ctx context.Context) map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()

	dsStatus := "ready"
	if p.supervisor != nil && !p.supervisor.IsRunning() {
		dsStatus = "stopped"
	}

	res := map[string]any{
		"downstream_status": dsStatus,
	}

	if p.cfg != nil {
		res["security"] = map[string]any{
			"masking":         p.cfg.Security.MaskingEnabled,
			"masking_mode":    p.cfg.Masking.Mode,
			"guardrails":      p.cfg.Security.GuardrailsEnabled,
			"audit":           p.cfg.Security.AuditEnabled,
			"ephemeral_creds": p.cfg.Security.EphemeralCredsEnabled,
		}
		res["downstream_transport"] = p.cfg.Downstream.Transport
	}

	return res
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
				fmt.Fprintf(os.Stderr, "[krypton] Client stdin closed (EOF). Gateway shutting down cleanly.\n")
				return err
			}
			parseErr := mcp.NewErrorResponse(mcp.RequestID{IsNull: true}, mcp.NewParseError(err.Error()))
			_ = p.clientWriter.WriteMessage(parseErr)
			continue
		}

		// Apply request interceptors in order
		p.mu.Lock()
		interceptors := make([]RequestInterceptor, len(p.reqInterceptors))
		copy(interceptors, p.reqInterceptors)
		p.mu.Unlock()

		intercepted := false
		var interceptResp *mcp.Response

		for _, interceptor := range interceptors {
			resp, shouldIntercept, err := interceptor(ctx, raw)
			if err != nil {
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
		if err := p.downstreamWriter.WriteMessage(raw); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return err
			}
			_ = rawBytes
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
