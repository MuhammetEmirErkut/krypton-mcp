package masker

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/krypton-mcp/krypton/pkg/mcp"
)

// MaskingResponseInterceptor inspects outbound messages from downstream servers and masks sensitive PII/secrets
func MaskingResponseInterceptor(tokenizer *Tokenizer) func(ctx context.Context, raw *mcp.RawMessage) (*mcp.RawMessage, error) {
	return func(ctx context.Context, raw *mcp.RawMessage) (*mcp.RawMessage, error) {
		if raw == nil || !raw.IsResponse() || raw.Result == nil || len(raw.Result) == 0 {
			return raw, nil
		}

		// Try parsing as CallToolResult
		var toolResult mcp.CallToolResult
		if err := json.Unmarshal(raw.Result, &toolResult); err == nil && len(toolResult.Content) > 0 {
			modified := false
			for i := range toolResult.Content {
				if toolResult.Content[i].Type == "text" && toolResult.Content[i].Text != "" {
					maskedText, count, err := tokenizer.MaskText(toolResult.Content[i].Text)
					if err == nil && count > 0 {
						toolResult.Content[i].Text = maskedText
						modified = true
					}
				}
			}

			if modified {
				data, err := json.Marshal(toolResult)
				if err != nil {
					return raw, fmt.Errorf("failed to marshal masked CallToolResult: %w", err)
				}
				raw.Result = data
			}
			return raw, nil
		}

		// Try parsing as ReadResourceResult
		var resResult mcp.ReadResourceResult
		if err := json.Unmarshal(raw.Result, &resResult); err == nil && len(resResult.Contents) > 0 {
			modified := false
			for i := range resResult.Contents {
				if resResult.Contents[i].Text != "" {
					maskedText, count, err := tokenizer.MaskText(resResult.Contents[i].Text)
					if err == nil && count > 0 {
						resResult.Contents[i].Text = maskedText
						modified = true
					}
				}
			}

			if modified {
				data, err := json.Marshal(resResult)
				if err != nil {
					return raw, fmt.Errorf("failed to marshal masked ReadResourceResult: %w", err)
				}
				raw.Result = data
			}
			return raw, nil
		}

		// Try parsing as GetPromptResult
		var promptResult mcp.GetPromptResult
		if err := json.Unmarshal(raw.Result, &promptResult); err == nil && len(promptResult.Messages) > 0 {
			modified := false
			for i := range promptResult.Messages {
				if promptResult.Messages[i].Content.Type == "text" && promptResult.Messages[i].Content.Text != "" {
					maskedText, count, err := tokenizer.MaskText(promptResult.Messages[i].Content.Text)
					if err == nil && count > 0 {
						promptResult.Messages[i].Content.Text = maskedText
						modified = true
					}
				}
			}

			if modified {
				data, err := json.Marshal(promptResult)
				if err != nil {
					return raw, fmt.Errorf("failed to marshal masked GetPromptResult: %w", err)
				}
				raw.Result = data
			}
			return raw, nil
		}

		// Fallback: Generic JSON value traversal
		var genericData any
		if err := json.Unmarshal(raw.Result, &genericData); err == nil {
			transformed, changed := maskGenericJSON(genericData, tokenizer)
			if changed {
				data, err := json.Marshal(transformed)
				if err != nil {
					return raw, err
				}
				raw.Result = data
			}
		}

		return raw, nil
	}
}

// DetokenizingRequestInterceptor inspects inbound client requests and detokenizes surrogate tokens before tool execution
func DetokenizingRequestInterceptor(tokenizer *Tokenizer) func(ctx context.Context, raw *mcp.RawMessage) (*mcp.Response, bool, error) {
	return func(ctx context.Context, raw *mcp.RawMessage) (*mcp.Response, bool, error) {
		if raw == nil || !raw.IsRequest() || raw.Params == nil || len(raw.Params) == 0 {
			return nil, false, nil
		}

		// Handle tools/call
		if raw.Method == mcp.MethodToolsCall {
			var params mcp.CallToolParams
			if err := json.Unmarshal(raw.Params, &params); err == nil && len(params.Arguments) > 0 {
				transformed, changed := unmaskMap(params.Arguments, tokenizer)
				if changed {
					params.Arguments = transformed
					data, err := json.Marshal(params)
					if err != nil {
						return nil, false, fmt.Errorf("failed to marshal detokenized CallToolParams: %w", err)
					}
					raw.Params = data
				}
			}
			return nil, false, nil
		}

		// Fallback: Generic JSON parameter traversal
		var genericParams any
		if err := json.Unmarshal(raw.Params, &genericParams); err == nil {
			transformed, changed := unmaskGenericJSON(genericParams, tokenizer)
			if changed {
				data, err := json.Marshal(transformed)
				if err != nil {
					return nil, false, err
				}
				raw.Params = data
			}
		}

		return nil, false, nil
	}
}

func maskGenericJSON(v any, tokenizer *Tokenizer) (any, bool) {
	switch val := v.(type) {
	case string:
		masked, count, err := tokenizer.MaskText(val)
		if err == nil && count > 0 {
			return masked, true
		}
		return val, false
	case map[string]any:
		changed := false
		newMap := make(map[string]any, len(val))
		for k, item := range val {
			res, ch := maskGenericJSON(item, tokenizer)
			newMap[k] = res
			if ch {
				changed = true
			}
		}
		return newMap, changed
	case []any:
		changed := false
		newList := make([]any, len(val))
		for i, item := range val {
			res, ch := maskGenericJSON(item, tokenizer)
			newList[i] = res
			if ch {
				changed = true
			}
		}
		return newList, changed
	default:
		return v, false
	}
}

func unmaskGenericJSON(v any, tokenizer *Tokenizer) (any, bool) {
	switch val := v.(type) {
	case string:
		unmasked, err := tokenizer.UnmaskText(val)
		if err == nil && unmasked != val {
			return unmasked, true
		}
		return val, false
	case map[string]any:
		return unmaskMap(val, tokenizer)
	case []any:
		changed := false
		newList := make([]any, len(val))
		for i, item := range val {
			res, ch := unmaskGenericJSON(item, tokenizer)
			newList[i] = res
			if ch {
				changed = true
			}
		}
		return newList, changed
	default:
		return v, false
	}
}

func unmaskMap(m map[string]any, tokenizer *Tokenizer) (map[string]any, bool) {
	changed := false
	newMap := make(map[string]any, len(m))
	for k, item := range m {
		res, ch := unmaskGenericJSON(item, tokenizer)
		newMap[k] = res
		if ch {
			changed = true
		}
	}
	return newMap, changed
}
