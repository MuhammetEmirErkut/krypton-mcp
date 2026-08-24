package credentials

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/krypton-mcp/krypton/pkg/mcp"
)

const (
	ToolRequestCredential = "krypton_request_credential"
	ToolRevokeCredential  = "krypton_revoke_credential"
	ToolListLeases        = "krypton_list_leases"
)

// RequestCredentialParams parameters for krypton_request_credential tool
type RequestCredentialParams struct {
	Target      string   `json:"target"`
	TTLSeconds  int      `json:"ttl_seconds,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// RevokeCredentialParams parameters for krypton_revoke_credential tool
type RevokeCredentialParams struct {
	LeaseID string `json:"lease_id"`
}

// BindCredentialTools registers JIT credential broker tools into an MCP Dispatcher
func BindCredentialTools(dispatcher *mcp.Dispatcher, broker *Broker) {
	if dispatcher == nil || broker == nil {
		return
	}

	// 1. Tool: Request Credential
	dispatcher.RegisterRequestHandler(ToolRequestCredential, func(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
		var params RequestCredentialParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &params); err != nil {
				return nil, mcp.NewInvalidParamsError("failed to parse request credential arguments: " + err.Error())
			}
		}

		if params.Target == "" {
			return nil, mcp.NewInvalidParamsError("missing required argument 'target'")
		}

		ttl := 15 * time.Minute
		if params.TTLSeconds > 0 {
			ttl = time.Duration(params.TTLSeconds) * time.Second
		}

		lease, err := broker.IssueLease(ctx, LeaseRequest{
			Target:      params.Target,
			Type:        TypeDatabase,
			TTL:         ttl,
			Permissions: params.Permissions,
		})
		if err != nil {
			return nil, mcp.NewInternalError(err.Error())
		}

		summary := fmt.Sprintf("Ephemeral credentials issued for '%s' (Lease ID: %s, Expires in %v)\nConnection Token / URI: %s",
			lease.Target, lease.ID, lease.TTL, lease.Token)

		return mcp.NewSuccessResponse(req.ID, mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.NewTextContent(summary),
			},
		})
	})

	// 2. Tool: Revoke Credential
	dispatcher.RegisterRequestHandler(ToolRevokeCredential, func(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
		var params RevokeCredentialParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &params); err != nil {
				return nil, mcp.NewInvalidParamsError("failed to parse revoke credential arguments: " + err.Error())
			}
		}

		if params.LeaseID == "" {
			return nil, mcp.NewInvalidParamsError("missing required argument 'lease_id'")
		}

		if err := broker.RevokeLease(ctx, params.LeaseID); err != nil {
			return nil, mcp.NewInternalError("failed to revoke lease: " + err.Error())
		}

		return mcp.NewSuccessResponse(req.ID, mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.NewTextContent(fmt.Sprintf("Lease '%s' has been successfully revoked.", params.LeaseID)),
			},
		})
	})

	// 3. Tool: List Leases
	dispatcher.RegisterRequestHandler(ToolListLeases, func(ctx context.Context, req *mcp.Request) (*mcp.Response, error) {
		leases := broker.ActiveLeases()
		type LeaseInfo struct {
			ID        string   `json:"id"`
			Target    string   `json:"target"`
			Type      string   `json:"type"`
			ExpiresAt string   `json:"expires_at"`
			Perms     []string `json:"permissions"`
		}

		list := make([]LeaseInfo, 0, len(leases))
		for _, l := range leases {
			list = append(list, LeaseInfo{
				ID:        l.ID,
				Target:    l.Target,
				Type:      string(l.Type),
				ExpiresAt: l.ExpiresAt.Format(time.RFC3339),
				Perms:     l.Permissions,
			})
		}

		data, err := json.MarshalIndent(list, "", "  ")
		if err != nil {
			return nil, mcp.NewInternalError("failed to format active leases: " + err.Error())
		}

		return mcp.NewSuccessResponse(req.ID, mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.NewTextContent(string(data)),
			},
		})
	})
}
