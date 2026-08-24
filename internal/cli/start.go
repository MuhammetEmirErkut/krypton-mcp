package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/krypton-mcp/krypton/internal/config"
	"github.com/krypton-mcp/krypton/internal/proxy"
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

			if cfg.Downstream.Command != "" {
				gw := proxy.NewSubprocessGatewayProxy(cfg, os.Stdin, os.Stdout)
				return gw.Start(ctx)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "🛡️  Starting KryptonMCP Gateway (Transport: %s)...\n", cfg.Server.Transport)
			return nil
		},
	}

	cmd.Flags().StringVar(&startTransport, "transport", "stdio", "Server transport ('stdio' or 'sse')")
	cmd.Flags().StringVar(&startHost, "host", "127.0.0.1", "Host address for SSE transport")
	cmd.Flags().IntVarP(&startPort, "port", "p", 8080, "Port for SSE transport")
	cmd.Flags().StringVar(&startDownstreamCmd, "downstream-cmd", "", "Command line for downstream MCP server")
	cmd.Flags().BoolVar(&startDryRun, "dry-run", false, "Validate configuration and pipeline without executing")

	return cmd
}
