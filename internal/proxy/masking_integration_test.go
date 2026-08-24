package proxy

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/krypton-mcp/krypton/internal/config"
	"github.com/krypton-mcp/krypton/pkg/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMasking_EndToEndMultiTurnIntegration(t *testing.T) {
	clientInPipeR, clientInPipeW := io.Pipe()
	clientOutPipeR, clientOutPipeW := io.Pipe()
	downstreamInPipeR, downstreamInPipeW := io.Pipe()
	downstreamOutPipeR, downstreamOutPipeW := io.Pipe()

	cfg := config.DefaultConfig()
	cfg.Security.MaskingEnabled = true

	proxy := NewGatewayProxy(cfg, GatewayStreams{
		ClientIn:      clientInPipeR,
		ClientOut:     clientOutPipeW,
		DownstreamIn:  downstreamOutPipeR,
		DownstreamOut: downstreamInPipeW,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_ = proxy.Start(ctx)
	}()

	clientWriter := mcp.NewFramingWriter(clientInPipeW)
	clientReader := mcp.NewFramingReader(clientOutPipeR)
	downstreamReader := mcp.NewFramingReader(downstreamInPipeR)
	downstreamWriter := mcp.NewFramingWriter(downstreamOutPipeW)

	// --- Turn 1: Client requests user profile ---
	req1, _ := mcp.NewRequest(mcp.NewIntID(1), "tools/call", mcp.CallToolParams{
		Name: "fetch_customer",
		Arguments: map[string]interface{}{
			"customer_id": "cust_12345",
		},
	})
	require.NoError(t, clientWriter.WriteMessage(req1))

	// Downstream receives request 1
	dsMsg1, _, err := downstreamReader.ReadMessage(ctx)
	require.NoError(t, err)
	assert.Equal(t, "tools/call", dsMsg1.Method)

	// Downstream responds with cleartext sensitive data
	cleartextCard := "4532-0150-1234-5671"
	cleartextEmail := "alice.smith@enterprise.com"
	dsResp1, _ := mcp.NewSuccessResponse(*dsMsg1.ID, mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.NewTextContent("Customer Profile: Alice Smith, Email: " + cleartextEmail + ", Card: " + cleartextCard),
		},
	})
	require.NoError(t, downstreamWriter.WriteMessage(dsResp1))

	// Client receives masked response
	clientResp1, _, err := clientReader.ReadMessage(ctx)
	require.NoError(t, err)
	assert.True(t, clientResp1.IsResponse())

	var toolResult1 mcp.CallToolResult
	require.NoError(t, json.Unmarshal(clientResp1.Result, &toolResult1))
	maskedText := toolResult1.Content[0].Text

	assert.NotContains(t, maskedText, cleartextEmail)
	assert.NotContains(t, maskedText, cleartextCard)
	assert.Contains(t, maskedText, "[EMAIL_REF_")
	assert.Contains(t, maskedText, "[CREDIT_CARD_REF_")

	// Extract the surrogate card token received by the client
	cardToken, err := proxy.Tokenizer().Vault().Put("credit_card", cleartextCard)
	require.NoError(t, err)
	assert.Contains(t, maskedText, cardToken)

	// --- Turn 2: Client LLM invokes next tool using the surrogate token ---
	req2, _ := mcp.NewRequest(mcp.NewIntID(2), "tools/call", mcp.CallToolParams{
		Name: "charge_payment",
		Arguments: map[string]interface{}{
			"card_number": cardToken,
			"amount_usd":  250,
		},
	})
	require.NoError(t, clientWriter.WriteMessage(req2))

	// Downstream receives request 2 with DETOKENIZED cleartext card number
	dsMsg2, _, err := downstreamReader.ReadMessage(ctx)
	require.NoError(t, err)
	assert.Equal(t, "tools/call", dsMsg2.Method)

	var dsParams2 mcp.CallToolParams
	require.NoError(t, json.Unmarshal(dsMsg2.Params, &dsParams2))
	assert.Equal(t, cleartextCard, dsParams2.Arguments["card_number"], "Downstream must receive unmasked cleartext card")
	assert.Equal(t, float64(250), dsParams2.Arguments["amount_usd"])

	// Downstream replies with payment receipt
	dsResp2, _ := mcp.NewSuccessResponse(*dsMsg2.ID, mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.NewTextContent("Payment authorized successfully for invoice #9921"),
		},
	})
	require.NoError(t, downstreamWriter.WriteMessage(dsResp2))

	// Client receives success confirmation
	clientResp2, _, err := clientReader.ReadMessage(ctx)
	require.NoError(t, err)
	assert.Contains(t, string(clientResp2.Result), "Payment authorized successfully")

	cancel()
	_ = clientInPipeW.Close()
	_ = downstreamOutPipeW.Close()
}
