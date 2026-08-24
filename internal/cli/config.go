package cli

import (
	"fmt"
	"os"

	"github.com/krypton-mcp/krypton/internal/config"
	"github.com/spf13/cobra"
)

// NewConfigCmd creates the 'config' command group
func NewConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage and validate KryptonMCP configuration files",
	}

	cmd.AddCommand(newConfigValidateCmd())
	cmd.AddCommand(newConfigInitCmd())

	return cmd
}

func newConfigValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate a KryptonMCP configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, _ := cmd.Flags().GetString("config")
			if path == "" && len(args) > 0 {
				path = args[0]
			}
			if path == "" {
				path = "krypton.yaml"
			}

			cfg, err := config.Load(path)
			if err != nil {
				return fmt.Errorf("configuration validation failed: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✓ Configuration file '%s' is valid (version: %s, transport: %s)\n",
				path, cfg.Version, cfg.Server.Transport)
			return nil
		},
	}
}

func newConfigInitCmd() *cobra.Command {
	var targetFile string

	cmd := &cobra.Command{
		Use:   "init [output-file]",
		Short: "Generate a production-grade template configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			dest := targetFile
			if (dest == "" || dest == "krypton.yaml") && len(args) > 0 {
				dest = args[0]
			}
			if dest == "" {
				dest = "krypton.yaml"
			}

			if _, err := os.Stat(dest); err == nil {
				return fmt.Errorf("target file '%s' already exists; will not overwrite", dest)
			}

			template := config.GenerateTemplateYAML()
			if err := os.WriteFile(dest, []byte(template), 0600); err != nil {
				return fmt.Errorf("failed to write configuration file '%s': %w", dest, err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✓ Created template configuration file at '%s'\n", dest)
			return nil
		},
	}

	cmd.Flags().StringVarP(&targetFile, "output", "o", "krypton.yaml", "Destination file path")
	return cmd
}
