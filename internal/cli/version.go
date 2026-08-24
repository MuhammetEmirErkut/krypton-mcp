package cli

import (
	"encoding/json"
	"fmt"

	"github.com/krypton-mcp/krypton/internal/version"
	"github.com/spf13/cobra"
)

// NewVersionCmd creates the 'version' subcommand
func NewVersionCmd() *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version and build metadata of KryptonMCP",
		RunE: func(cmd *cobra.Command, args []string) error {
			info := version.Get()
			if asJSON {
				data, err := json.MarshalIndent(info, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to format version as json: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(data))
				return nil
			}

			fmt.Fprintln(cmd.OutOrStdout(), info.String())
			return nil
		},
	}

	cmd.Flags().BoolVarP(&asJSON, "json", "j", false, "Output version information in JSON format")
	return cmd
}
