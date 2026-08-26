package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// MessageHandler is a function that processes an incoming MCP RawMessage and produces a Response
type MessageHandler func(ctx context.Context, req *RawMessage) (*Response, error)

// HealthStatusProvider returns health and readiness metadata for health check endpoints
type HealthStatusProvider interface {
	HealthStatus(ctx context.Context) map[string]any
}

// SSEServer provides an HTTP / Server-Sent Events transport server for MCP clients
type SSEServer struct {
	addr           string
	handler        MessageHandler
	healthProvider HealthStatusProvider
	server         *http.Server
	startTime      time.Time

	mu       sync.RWMutex
	sessions map[string]chan []byte
}

// NewSSEServer creates a new SSEServer listening on the specified host:port
func NewSSEServer(addr string, handler MessageHandler, healthProvider HealthStatusProvider) *SSEServer {
	s := &SSEServer{
		addr:           addr,
		handler:        handler,
		healthProvider: healthProvider,
		startTime:      time.Now(),
		sessions:       make(map[string]chan []byte),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/sse", s.handleSSE)
	mux.HandleFunc("/message", s.handleMessage)
	mux.HandleFunc("/rpc", s.handleDirectRPC)
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/live", s.handleHealth)
	mux.HandleFunc("/ready", s.handleReady)

	s.server = &http.Server{
		Addr:              addr,
		Handler:           s.corsMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	return s
}

// Start launches the HTTP/SSE server in a blocking call, shutting down when context is cancelled
func (s *SSEServer) Start(ctx context.Context) error {
	errCh := make(chan error, 1)

	go func() {
		if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.server.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// Close gracefully closes the HTTP server
func (s *SSEServer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

func (s *SSEServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Session-Id")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *SSEServer) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported by server", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	sessionID := generateSessionID()
	msgCh := make(chan []byte, 64)

	s.mu.Lock()
	s.sessions[sessionID] = msgCh
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.sessions, sessionID)
		close(msgCh)
		s.mu.Unlock()
	}()

	// Send initial endpoint event
	endpointURI := fmt.Sprintf("/message?sessionId=%s", sessionID)
	fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", endpointURI)
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-msgCh:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(msg))
			flusher.Flush()
		}
	}
}

func (s *SSEServer) handleMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("sessionId")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var raw RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		http.Error(w, "Invalid JSON-RPC payload", http.StatusBadRequest)
		return
	}

	if s.handler == nil {
		http.Error(w, "No message handler configured", http.StatusInternalServerError)
		return
	}

	resp, err := s.handler(r.Context(), &raw)
	if err != nil {
		if raw.ID != nil {
			resp = NewErrorResponse(*raw.ID, NewInternalError(err.Error()))
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if resp == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	// If session is active on SSE, send message event
	if sessionID != "" {
		s.mu.RLock()
		ch, exists := s.sessions[sessionID]
		s.mu.RUnlock()
		if exists && ch != nil {
			select {
			case ch <- respBytes:
			default:
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

func (s *SSEServer) handleDirectRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.handleMessage(w, r)
}

func (s *SSEServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" && r.Method == http.MethodPost {
		s.handleMessage(w, r)
		return
	}
	if r.URL.Path == "/" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"service":     "KryptonMCP Gateway",
			"description": "Zero-Trust Security & Privacy Gateway for AI Agents",
			"status":      "running",
			"sse_url":     "/sse",
			"rpc_url":     "/message",
			"health_url":  "/health",
		})
		return
	}
	http.NotFound(w, r)
}

func (s *SSEServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	activeSessions := len(s.sessions)
	s.mu.RUnlock()

	status := map[string]any{
		"status":          "ok",
		"version":         "v1",
		"transport":       "sse",
		"uptime_seconds":  int(time.Since(s.startTime).Seconds()),
		"active_sessions": activeSessions,
	}

	if s.healthProvider != nil {
		for k, v := range s.healthProvider.HealthStatus(r.Context()) {
			status[k] = v
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(status)
}

func (s *SSEServer) handleReady(w http.ResponseWriter, r *http.Request) {
	status := map[string]any{
		"status":    "ready",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	if s.healthProvider != nil {
		for k, v := range s.healthProvider.HealthStatus(r.Context()) {
			status[k] = v
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(status)
}

func generateSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
