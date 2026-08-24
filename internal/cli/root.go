package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// NewRootCmd initializes the base krypton command
func NewRootCmd() *cobra.Command {
	var (
		cfgFile  string
		logLevel string
		verbose  bool
	)

	rootCmd := &cobra.Command{
		Use:   "krypton",
		Short: "KryptonMCP - The Zero-Trust Security Gateway for AI Agents",
		Long: `KryptonMCP is a standalone, zero-dependency Zero-Trust Security & Privacy Gateway 
positioned between AI agents (Claude Desktop, Cursor, Windsurf) and backend infrastructures 
(PostgreSQL, Redis, AWS, REST APIs).

It provides in-flight PII masking, JIT ephemeral credentials, prompt-injection guardrails,
and a cryptographically signed Merkle audit ledger.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Path to configuration file (default is ./krypton.yaml or $KRYPTON_CONFIG)")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "info", "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	rootCmd.AddCommand(NewVersionCmd())
	rootCmd.AddCommand(NewConfigCmd())
	rootCmd.AddCommand(NewStartCmd())
	rootCmd.AddCommand(NewAuditCmd())

	return rootCmd
}

// Execute runs the root command
func Execute() error {
	cmd := NewRootCmd()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return err
	}
	return nil
}
