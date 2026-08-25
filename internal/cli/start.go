package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/krypton-mcp/krypton/internal/config"
	"github.com/krypton-mcp/krypton/internal/proxy"
	"github.com/krypton-mcp/krypton/pkg/audit"
	"github.com/krypton-mcp/krypton/pkg/credentials"
	"github.com/krypton-mcp/krypton/pkg/guardrails"
	"github.com/krypton-mcp/krypton/pkg/mcp"
	"github.com/spf13/cobra"
)

// NewStartCmd creates the 'start' command to launch the Krypton gateway
func NewStartCmd() *cobra.Command {
	var (
		startTransport     string
		startHost          string
		startPort          int
		startDownstreamCmd string
		startDryRun        bool
	)

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the KryptonMCP security gateway",
		Long: `Start launches the KryptonMCP Zero-Trust Security Gateway. 
It intercepts Model Context Protocol messages, applies in-flight data masking,
enforces guardrails, and signs audit logs.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			configFile, _ := cmd.Flags().GetString("config")
			if configFile == "" {
				if _, err := os.Stat("krypton.yaml"); err == nil {
					configFile = "krypton.yaml"
				}
			}

			cfg, err := config.Load(configFile)
			if err != nil {
				return fmt.Errorf("failed to load gateway configuration: %w", err)
			}

			if cmd.Flags().Changed("transport") {
				cfg.Server.Transport = startTransport
			}
			if cmd.Flags().Changed("host") {
				cfg.Server.Host = startHost
			}
			if cmd.Flags().Changed("port") {
				cfg.Server.Port = startPort
			}
			if cmd.Flags().Changed("downstream-cmd") {
				cfg.Downstream.Command = startDownstreamCmd
			}

			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("invalid runtime configuration: %w", err)
			}

			if startDryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "✓ KryptonMCP configuration validated successfully (dry-run mode).\n")
				fmt.Fprintf(cmd.OutOrStdout(), "  Transport: %s\n", cfg.Server.Transport)
				fmt.Fprintf(cmd.OutOrStdout(), "  Downstream Command: %s\n", cfg.Downstream.Command)
				fmt.Fprintf(cmd.OutOrStdout(), "  Masking Enabled: %t (Mode: %s)\n", cfg.Security.MaskingEnabled, cfg.Masking.Mode)
				fmt.Fprintf(cmd.OutOrStdout(), "  Guardrails Enabled: %t\n", cfg.Security.GuardrailsEnabled)
				fmt.Fprintf(cmd.OutOrStdout(), "  Audit Enabled: %t (Log: %s)\n", cfg.Security.AuditEnabled, cfg.Audit.LogPath)
				return nil
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			if len(args) > 0 {
				cfg.Downstream.Command = args[0]
				cfg.Downstream.Args = args[1:]
			}

			if cfg.Downstream.Command != "" {
				gw := proxy.NewSubprocessGatewayProxy(cfg, os.Stdin, os.Stdout)
				return gw.Start(ctx)
			}

			// Standalone MCP Server Mode
			disp := mcp.NewDispatcher()
			disp.BindStandardHandlers("krypton-gateway", "0.1.0-dev")

			var auditWriter *audit.LogWriter
			if cfg.Security.AuditEnabled && cfg.Audit.LogPath != "" {
				w, err := audit.NewFileWriter(cfg.Audit.LogPath)
				if err == nil {
					auditWriter = w
					defer w.Close()
				}
			}

			var injectionDetector *guardrails.InjectionDetector
			var policyEngine *guardrails.PolicyEngine
			if cfg.Security.GuardrailsEnabled {
				injectionDetector = guardrails.NewInjectionDetector()
				policyEngine, _ = guardrails.NewPolicyEngine(nil)
			}

			broker := credentials.NewBroker()
			defer broker.Shutdown(ctx)
			credentials.BindCredentialTools(disp, broker)

			// Guardrails Middleware
			if injectionDetector != nil {
				disp.Use(func(ctx context.Context, req *mcp.Request, next mcp.RequestHandlerFunc) (*mcp.Response, error) {
					reqID := req.ID
					rawMsg := &mcp.RawMessage{
						JSONRPC: req.JSONRPC,
						ID:      &reqID,
						Method:  req.Method,
						Params:  req.Params,
					}

					resp, blocked, err := guardrails.GuardrailRequestInterceptor(injectionDetector, policyEngine, cfg.Guardrails.MaxPromptSizeBytes)(ctx, rawMsg)
					if err != nil {
						return nil, err
					}
					if blocked {
						return resp, nil
					}
					return next(ctx, req)
				})
			}

			// Audit Logging Middleware
			if auditWriter != nil {
				disp.Use(func(ctx context.Context, req *mcp.Request, next mcp.RequestHandlerFunc) (*mcp.Response, error) {
					evtType := audit.EventMCPRequest
					if req.Method == mcp.MethodToolsCall {
						evtType = audit.EventToolExecution
					}
					evt := audit.NewAuditEvent(evtType, "client", req.Method, req.Params, nil)
					_ = auditWriter.WriteEvent(evt)

					resp, err := next(ctx, req)
					if resp != nil {
						resBytes, _ := json.Marshal(resp.Result)
						respEvt := audit.NewAuditEvent(audit.EventMCPResponse, "gateway", req.Method, resBytes, nil)
						_ = auditWriter.WriteEvent(respEvt)
					}
					return resp, err
				})
			}

			reader := mcp.NewFramingReader(os.Stdin)
			writer := mcp.NewFramingWriter(os.Stdout)

			for {
				raw, _, err := reader.ReadMessage(ctx)
				if err != nil {
					if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
						return nil
					}
					return err
				}

				if raw.IsRequest() {
					resp, err := disp.Dispatch(ctx, raw)
					if err != nil {
						resp = mcp.NewErrorResponse(*raw.ID, mcp.NewInternalError(err.Error()))
					}
					if resp != nil {
						if err := writer.WriteMessage(resp); err != nil {
							return err
						}
					}
				}
			}
		},
	}

	cmd.Flags().StringVar(&startTransport, "transport", "stdio", "Server transport ('stdio' or 'sse')")
	cmd.Flags().StringVar(&startHost, "host", "127.0.0.1", "Host address for SSE transport")
	cmd.Flags().IntVarP(&startPort, "port", "p", 8080, "Port for SSE transport")
	cmd.Flags().StringVar(&startDownstreamCmd, "downstream-cmd", "", "Command line for downstream MCP server")
	cmd.Flags().BoolVar(&startDryRun, "dry-run", false, "Validate configuration and pipeline without executing")

	return cmd
}
