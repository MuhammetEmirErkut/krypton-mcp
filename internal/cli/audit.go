package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/krypton-mcp/krypton/pkg/audit"
	"github.com/spf13/cobra"
)

// NewAuditCmd creates the `krypton audit` parent command
func NewAuditCmd() *cobra.Command {
	auditCmd := &cobra.Command{
		Use:   "audit",
		Short: "Manage and cryptographically verify Merkle audit ledgers",
		Long:  "Commands for generating Ed25519 audit signing keys, verifying log file integrity, and exporting Merkle proofs.",
	}

	auditCmd.AddCommand(newAuditKeygenCmd())
	auditCmd.AddCommand(newAuditVerifyCmd())
	auditCmd.AddCommand(newAuditProofCmd())

	return auditCmd
}

func newAuditKeygenCmd() *cobra.Command {
	var (
		outDir   string
		privPath string
		pubPath  string
	)

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a new Ed25519 keypair for cryptographic audit signing",
		RunE: func(cmd *cobra.Command, args []string) error {
			kp, err := audit.GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("failed to generate keypair: %w", err)
			}

			if privPath == "" {
				privPath = filepath.Join(outDir, "krypton_audit.key")
			}
			if pubPath == "" {
				pubPath = filepath.Join(outDir, "krypton_audit.pub")
			}

			if err := audit.SaveKeyPair(kp, privPath, pubPath); err != nil {
				return fmt.Errorf("failed to save keypair: %w", err)
			}

			keyID := audit.KeyID(kp.PublicKey)
			fmt.Printf("✅ Successfully generated Ed25519 audit keypair (KeyID: %s)\n", keyID)
			fmt.Printf("   Private Key: %s (mode 0600)\n", privPath)
			fmt.Printf("   Public Key:  %s (mode 0644)\n", pubPath)
			return nil
		},
	}

	cmd.Flags().StringVarP(&outDir, "out-dir", "o", ".", "Directory to output keys into")
	cmd.Flags().StringVarP(&privPath, "priv-key", "k", "", "Path for private key output")
	cmd.Flags().StringVarP(&pubPath, "pub-key", "p", "", "Path for public key output")
	return cmd
}

func newAuditVerifyCmd() *cobra.Command {
	var (
		logFile string
		pubKey  string
	)

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Cryptographically verify the integrity of an audit log file",
		RunE: func(cmd *cobra.Command, args []string) error {
			if logFile == "" {
				return fmt.Errorf("--log-file is required")
			}

			var pub ed25519PublicKeyWrapper
			if pubKey != "" {
				pk, err := audit.LoadPublicKey(pubKey)
				if err != nil {
					return fmt.Errorf("failed to load public key: %w", err)
				}
				pub.key = pk
			}

			report, err := audit.VerifyLogFile(logFile, pub.key)
			if err != nil {
				return fmt.Errorf("verification error: %w", err)
			}

			if report.Valid {
				fmt.Printf("✅ Audit ledger verification PASSED\n")
				fmt.Printf("   Total Events:   %d\n", report.TotalEvents)
				fmt.Printf("   Final Merkle Root: %s\n", report.ComputedRoot)
				return nil
			}

			fmt.Fprintf(os.Stderr, "❌ Audit ledger verification FAILED (%d errors detected):\n", len(report.Errors))
			for i, e := range report.Errors {
				fmt.Fprintf(os.Stderr, "   [%d] %s\n", i+1, e)
			}
			return fmt.Errorf("audit ledger verification failed")
		},
	}

	cmd.Flags().StringVarP(&logFile, "log-file", "f", "audit.jsonl", "Path to audit JSONL file")
	cmd.Flags().StringVarP(&pubKey, "public-key", "k", "", "Path to Ed25519 public key file for signature verification")
	return cmd
}

func newAuditProofCmd() *cobra.Command {
	var (
		logFile string
		index   int64
	)

	cmd := &cobra.Command{
		Use:   "proof",
		Short: "Export a cryptographic inclusion proof for a specific audit log index",
		RunE: func(cmd *cobra.Command, args []string) error {
			if logFile == "" {
				return fmt.Errorf("--log-file is required")
			}

			proof, err := audit.ExportProofFromLog(logFile, index)
			if err != nil {
				return fmt.Errorf("failed to generate proof: %w", err)
			}

			data, err := json.MarshalIndent(proof, "", "  ")
			if err != nil {
				return err
			}

			fmt.Println(string(data))
			return nil
		},
	}

	cmd.Flags().StringVarP(&logFile, "log-file", "f", "audit.jsonl", "Path to audit JSONL file")
	cmd.Flags().Int64VarP(&index, "index", "i", 0, "Zero-based index of the audit event")
	return cmd
}

type ed25519PublicKeyWrapper struct {
	key []byte
}
