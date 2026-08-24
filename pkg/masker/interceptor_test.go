package masker

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/krypton-mcp/krypton/pkg/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaskingResponseInterceptor_CallToolResult(t *testing.T) {
	tokenizer, err := NewTokenizer(nil, nil)
	require.NoError(t, err)

	respInterceptor := MaskingResponseInterceptor(tokenizer)

	toolResult := mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.NewTextContent("Found customer: Alice, Email: alice@corp.com, Card: 4532-0150-1234-5671"),
		},
	}
	resBytes, err := json.Marshal(toolResult)
	require.NoError(t, err)

	raw := &mcp.RawMessage{
		JSONRPC: mcp.JSONRPCVersion,
		ID:      &mcp.RequestID{IntVal: 1},
		Result:  resBytes,
	}

	modified, err := respInterceptor(context.Background(), raw)
	require.NoError(t, err)
	require.NotNil(t, modified)

	var maskedResult mcp.CallToolResult
	require.NoError(t, json.Unmarshal(modified.Result, &maskedResult))
	require.Len(t, maskedResult.Content, 1)

	maskedText := maskedResult.Content[0].Text
	assert.NotContains(t, maskedText, "alice@corp.com")
	assert.NotContains(t, maskedText, "4532-0150-1234-5671")
	assert.Contains(t, maskedText, "[EMAIL_REF_")
	assert.Contains(t, maskedText, "[CREDIT_CARD_REF_")
}

func TestMaskingResponseInterceptor_ReadResourceResult(t *testing.T) {
	tokenizer, err := NewTokenizer(nil, nil)
	require.NoError(t, err)

	respInterceptor := MaskingResponseInterceptor(tokenizer)

	resResult := mcp.ReadResourceResult{
		Contents: []mcp.ResourceContent{
			{
				URI:      "postgres://users/1",
				MIMEType: "text/plain",
				Text:     "Secret key: AKIAIOSFODNN7EXAMPLE",
			},
		},
	}
	resBytes, _ := json.Marshal(resResult)

	raw := &mcp.RawMessage{
		JSONRPC: mcp.JSONRPCVersion,
		ID:      &mcp.RequestID{IntVal: 2},
		Result:  resBytes,
	}

	modified, err := respInterceptor(context.Background(), raw)
	require.NoError(t, err)

	var maskedRes mcp.ReadResourceResult
	require.NoError(t, json.Unmarshal(modified.Result, &maskedRes))
	assert.NotContains(t, maskedRes.Contents[0].Text, "AKIAIOSFODNN7EXAMPLE")
	assert.Contains(t, maskedRes.Contents[0].Text, "[AWS_KEY_REF_")
}

func TestMaskingResponseInterceptor_GetPromptResult(t *testing.T) {
	tokenizer, err := NewTokenizer(nil, nil)
	require.NoError(t, err)

	respInterceptor := MaskingResponseInterceptor(tokenizer)

	promptResult := mcp.GetPromptResult{
		Messages: []mcp.PromptMessage{
			{
				Role:    "user",
				Content: mcp.NewTextContent("Call me at 555-432-1098"),
			},
		},
	}
	resBytes, _ := json.Marshal(promptResult)

	raw := &mcp.RawMessage{
		JSONRPC: mcp.JSONRPCVersion,
		ID:      &mcp.RequestID{IntVal: 3},
		Result:  resBytes,
	}

	modified, err := respInterceptor(context.Background(), raw)
	require.NoError(t, err)

	var maskedPrompt mcp.GetPromptResult
	require.NoError(t, json.Unmarshal(modified.Result, &maskedPrompt))
	assert.NotContains(t, maskedPrompt.Messages[0].Content.Text, "555-432-1098")
	assert.Contains(t, maskedPrompt.Messages[0].Content.Text, "[PHONE_REF_")
}

func TestDetokenizingRequestInterceptor_CallTool(t *testing.T) {
	tokenizer, err := NewTokenizer(nil, nil)
	require.NoError(t, err)

	// Pre-populate vault with email token
	originalEmail := "bob@enterprise.com"
	emailToken, err := tokenizer.Vault().Put("email", originalEmail)
	require.NoError(t, err)

	reqInterceptor := DetokenizingRequestInterceptor(tokenizer)

	callParams := mcp.CallToolParams{
		Name: "send_email",
		Arguments: map[string]interface{}{
			"recipient": emailToken,
			"subject":   "Meeting Notes",
		},
	}
	paramBytes, _ := json.Marshal(callParams)

	raw := &mcp.RawMessage{
		JSONRPC: mcp.JSONRPCVersion,
		ID:      &mcp.RequestID{IntVal: 10},
		Method:  mcp.MethodToolsCall,
		Params:  paramBytes,
	}

	resp, intercepted, err := reqInterceptor(context.Background(), raw)
	require.NoError(t, err)
	assert.False(t, intercepted)
	assert.Nil(t, resp)

	// Verify params were modified to restore original email
	var unmaskedParams mcp.CallToolParams
	require.NoError(t, json.Unmarshal(raw.Params, &unmaskedParams))
	assert.Equal(t, originalEmail, unmaskedParams.Arguments["recipient"])
	assert.Equal(t, "Meeting Notes", unmaskedParams.Arguments["subject"])
}
