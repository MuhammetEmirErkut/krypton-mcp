package credentials

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/krypton-mcp/krypton/pkg/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBindCredentialTools_MCPDispatch(t *testing.T) {
	broker := NewBroker(WithTTLBounds(10*time.Millisecond, 1*time.Hour, 10*time.Minute))
	dispatcher := mcp.NewDispatcher()

	BindCredentialTools(dispatcher, broker)

	// 1. Invoke krypton_request_credential tool
	reqParams, _ := json.Marshal(RequestCredentialParams{
		Target:      "generic_token",
		TTLSeconds:  300,
		Permissions: []string{"read"},
	})

	reqMsg := &mcp.RawMessage{
		JSONRPC: mcp.JSONRPCVersion,
		ID:      &mcp.RequestID{IntVal: 1},
		Method:  ToolRequestCredential,
		Params:  reqParams,
	}

	resp, err := dispatcher.Dispatch(context.Background(), reqMsg)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)
	assert.Contains(t, string(resp.Result), "Ephemeral credentials issued")

	// 2. Invoke krypton_list_leases
	listMsg := &mcp.RawMessage{
		JSONRPC: mcp.JSONRPCVersion,
		ID:      &mcp.RequestID{IntVal: 2},
		Method:  ToolListLeases,
	}

	listResp, err := dispatcher.Dispatch(context.Background(), listMsg)
	require.NoError(t, err)
	assert.Nil(t, listResp.Error)
	assert.Contains(t, string(listResp.Result), "generic_token")

	// Extract lease ID
	active := broker.ActiveLeases()
	require.Len(t, active, 1)
	leaseID := active[0].ID

	// 3. Invoke krypton_revoke_credential
	revokeParams, _ := json.Marshal(RevokeCredentialParams{
		LeaseID: leaseID,
	})

	revokeMsg := &mcp.RawMessage{
		JSONRPC: mcp.JSONRPCVersion,
		ID:      &mcp.RequestID{IntVal: 3},
		Method:  ToolRevokeCredential,
		Params:  revokeParams,
	}

	revokeResp, err := dispatcher.Dispatch(context.Background(), revokeMsg)
	require.NoError(t, err)
	assert.Nil(t, revokeResp.Error)
	assert.Contains(t, string(revokeResp.Result), "successfully revoked")
	assert.Equal(t, 0, len(broker.ActiveLeases()))
}

func TestBindCredentialTools_ValidationErrors(t *testing.T) {
	broker := NewBroker()
	dispatcher := mcp.NewDispatcher()
	BindCredentialTools(dispatcher, broker)

	// Missing target in request
	badReq, _ := json.Marshal(RequestCredentialParams{Target: ""})
	resp, _ := dispatcher.Dispatch(context.Background(), &mcp.RawMessage{
		JSONRPC: mcp.JSONRPCVersion,
		ID:      &mcp.RequestID{IntVal: 10},
		Method:  ToolRequestCredential,
		Params:  badReq,
	})
	require.NotNil(t, resp.Error)
	assert.Equal(t, mcp.CodeInvalidParams, resp.Error.Code)

	// Missing lease_id in revoke
	badRevoke, _ := json.Marshal(RevokeCredentialParams{LeaseID: ""})
	resp, _ = dispatcher.Dispatch(context.Background(), &mcp.RawMessage{
		JSONRPC: mcp.JSONRPCVersion,
		ID:      &mcp.RequestID{IntVal: 11},
		Method:  ToolRevokeCredential,
		Params:  badRevoke,
	})
	require.NotNil(t, resp.Error)
	assert.Equal(t, mcp.CodeInvalidParams, resp.Error.Code)

	// Revoking non-existent lease
	missingLease, _ := json.Marshal(RevokeCredentialParams{LeaseID: "non_existent_123"})
	resp, _ = dispatcher.Dispatch(context.Background(), &mcp.RawMessage{
		JSONRPC: mcp.JSONRPCVersion,
		ID:      &mcp.RequestID{IntVal: 12},
		Method:  ToolRevokeCredential,
		Params:  missingLease,
	})
	require.NotNil(t, resp.Error)
	assert.Equal(t, mcp.CodeInternalError, resp.Error.Code)
}
