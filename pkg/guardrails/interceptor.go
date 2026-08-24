package guardrails

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/krypton-mcp/krypton/pkg/mcp"
)

// GuardrailRequestInterceptor inspects inbound client requests and enforces prompt injection defense,
// tool RBAC policies, parameter constraints, and payload size bounds.
func GuardrailRequestInterceptor(detector *InjectionDetector, policy *PolicyEngine, maxSizeBytes int64) func(ctx context.Context, raw *mcp.RawMessage) (*mcp.Response, bool, error) {
	if maxSizeBytes <= 0 {
		maxSizeBytes = 1024 * 1024 // 1 MB default
	}

	return func(ctx context.Context, raw *mcp.RawMessage) (*mcp.Response, bool, error) {
		if raw == nil || !raw.IsRequest() {
			return nil, false, nil
		}

		// 1. Check max payload size
		if int64(len(raw.Params)) > maxSizeBytes {
			return mcp.NewErrorResponse(*raw.ID, mcp.NewSecurityBlockedError("request payload exceeds max allowed size limit")), true, nil
		}

		// 2. Check for Prompt-Injection & Threat Heuristics
		if detector != nil && len(raw.Params) > 0 {
			report := detector.ScanText(string(raw.Params))
			if report.Detected {
				return mcp.NewErrorResponse(*raw.ID, mcp.NewSecurityBlockedError(fmt.Sprintf("prompt injection detected: %s", report.Reason))), true, nil
			}
		}

		// 3. Check Tool RBAC & Parameter Constraints
		if policy != nil && raw.Method == mcp.MethodToolsCall && len(raw.Params) > 0 {
			var params mcp.CallToolParams
			if err := json.Unmarshal(raw.Params, &params); err == nil {
				// Deep scan arguments for injection
				if detector != nil {
					argReport := detector.ScanArguments(params.Arguments)
					if argReport.Detected {
						return mcp.NewErrorResponse(*raw.ID, mcp.NewSecurityBlockedError(fmt.Sprintf("injection detected in tool arguments: %s", argReport.Reason))), true, nil
					}
				}

				// Evaluate RBAC & constraints
				allowed, reason := policy.EvaluateToolCall(params.Name, params.Arguments)
				if !allowed {
					return mcp.NewErrorResponse(*raw.ID, mcp.NewSecurityBlockedError(reason)), true, nil
				}
			}
		}

		return nil, false, nil
	}
}
