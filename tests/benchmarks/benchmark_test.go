package benchmarks

import (
	"fmt"
	"testing"

	"github.com/krypton-mcp/krypton/internal/config"
	"github.com/krypton-mcp/krypton/pkg/audit"
	"github.com/krypton-mcp/krypton/pkg/guardrails"
	"github.com/krypton-mcp/krypton/pkg/masker"
)

func BenchmarkMasker_EndToEndMaskText(b *testing.B) {
	tok, _ := masker.NewTokenizer(&config.MaskingConfig{Mode: "tokenize"}, nil)
	payload := "User alice.smith@corp.com updated payment card 4532-0150-1234-5671 and SSN 000-12-3456 from IP 192.168.1.10"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _, _ = tok.MaskText(payload)
	}
}

func BenchmarkGuardrails_InjectionScan(b *testing.B) {
	detector := guardrails.NewInjectionDetector()
	payload := "Please review the attached code and prepare a pull request for the engineering team."

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = detector.ScanText(payload)
	}
}

func BenchmarkAudit_MerkleTreeAppend(b *testing.B) {
	tree := audit.NewMerkleTree()
	data := []byte("event-payload-sha256-digest-benchmark")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		tree.Append(data)
	}
}

func BenchmarkGateway_FullPipeline(b *testing.B) {
	tok, _ := masker.NewTokenizer(&config.MaskingConfig{Mode: "tokenize"}, nil)
	detector := guardrails.NewInjectionDetector()
	tree := audit.NewMerkleTree()

	sampleText := "Hello, contact support at security@acme.org regarding card 4532-0150-1234-5671"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// 1. Guardrail inspection
		_ = detector.ScanText(sampleText)

		// 2. In-flight Masking
		masked, _, _ := tok.MaskText(sampleText)

		// 3. Merkle Audit Ledger append
		evt := audit.NewAuditEvent(audit.EventMCPRequest, "client", "tools/call", []byte(masked), nil)
		_, _, _ = tree.AppendEvent(evt)
	}
}

func TestBenchmarkHarness(t *testing.T) {
	// Simple test to ensure benchmark package compiles and runs
	tok, err := masker.NewTokenizer(&config.MaskingConfig{Mode: "tokenize"}, nil)
	if err != nil {
		t.Fatalf("failed to create tokenizer: %v", err)
	}
	masked, count, err := tok.MaskText("test user@domain.com")
	if err != nil || count == 0 {
		t.Fatalf("expected masking, got %s, count %d", masked, count)
	}
	fmt.Println("Benchmark harness verified.")
}
