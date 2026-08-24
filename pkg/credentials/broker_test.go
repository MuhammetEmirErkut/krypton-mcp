package credentials

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSecurePassword(t *testing.T) {
	pwd, err := GenerateSecurePassword(32)
	require.NoError(t, err)
	assert.Len(t, pwd, 32)

	pwd2, err := GenerateSecurePassword(32)
	require.NoError(t, err)
	assert.NotEqual(t, pwd, pwd2, "Subsequent passwords must be distinct")
}

func TestBroker_IssueAndManualRevoke(t *testing.T) {
	broker := NewBroker(WithTTLBounds(10*time.Millisecond, 1*time.Hour, 10*time.Minute))

	req := LeaseRequest{
		Target:      "generic_token",
		Type:        TypeAPIToken,
		TTL:         5 * time.Minute,
		Permissions: []string{"read", "write"},
		Metadata:    map[string]string{"user": "alice"},
	}

	lease, err := broker.IssueLease(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, lease)
	assert.NotEmpty(t, lease.ID)
	assert.NotEmpty(t, lease.Token)
	assert.False(t, lease.Revoked)
	assert.False(t, lease.IsExpired())
	assert.Equal(t, 1, len(broker.ActiveLeases()))

	// Manual early revocation
	err = broker.RevokeLease(context.Background(), lease.ID)
	require.NoError(t, err)

	fetched, err := broker.GetLease(lease.ID)
	require.NoError(t, err)
	assert.True(t, fetched.Revoked)
	assert.True(t, fetched.IsExpired())
	assert.Equal(t, 0, len(broker.ActiveLeases()))
}

func TestBroker_AutomatedBackgroundRevocation(t *testing.T) {
	// Set 20ms TTL for fast test execution
	broker := NewBroker(WithTTLBounds(5*time.Millisecond, 1*time.Hour, 20*time.Millisecond))

	req := LeaseRequest{
		Target: "generic_token",
		TTL:    25 * time.Millisecond,
	}

	lease, err := broker.IssueLease(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, lease.Revoked)

	// Wait for background timer to trigger auto-revocation
	time.Sleep(50 * time.Millisecond)

	fetched, err := broker.GetLease(lease.ID)
	require.NoError(t, err)
	assert.True(t, fetched.Revoked, "Lease must be automatically revoked after TTL expiry")
}

func TestBroker_InvalidTTL(t *testing.T) {
	broker := NewBroker(WithTTLBounds(1*time.Second, 10*time.Second, 5*time.Second))

	// Too high
	_, err := broker.IssueLease(context.Background(), LeaseRequest{
		Target: "generic_token",
		TTL:    1 * time.Hour,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidTTL)

	// Too low
	_, err = broker.IssueLease(context.Background(), LeaseRequest{
		Target: "generic_token",
		TTL:    100 * time.Millisecond,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidTTL)
}

func TestBroker_RenewLease(t *testing.T) {
	broker := NewBroker(WithTTLBounds(10*time.Millisecond, 1*time.Hour, 10*time.Minute))

	lease, err := broker.IssueLease(context.Background(), LeaseRequest{
		Target: "generic_token",
		TTL:    1 * time.Minute,
	})
	require.NoError(t, err)

	renewed, err := broker.RenewLease(context.Background(), lease.ID, 5*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, renewed.TTL)
}

func TestBroker_Shutdown(t *testing.T) {
	broker := NewBroker()

	for i := 0; i < 5; i++ {
		_, err := broker.IssueLease(context.Background(), LeaseRequest{
			Target: "generic_token",
			TTL:    10 * time.Minute,
		})
		require.NoError(t, err)
	}

	assert.Equal(t, 5, len(broker.ActiveLeases()))

	err := broker.Shutdown(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 0, len(broker.ActiveLeases()))
}

func TestBroker_ConcurrentAccess(t *testing.T) {
	broker := NewBroker(WithTTLBounds(10*time.Millisecond, 1*time.Hour, 10*time.Minute))

	var wg sync.WaitGroup
	numWorkers := 30

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lease, err := broker.IssueLease(context.Background(), LeaseRequest{
				Target: "generic_token",
				TTL:    5 * time.Minute,
			})
			if assert.NoError(t, err) {
				_ = broker.RevokeLease(context.Background(), lease.ID)
			}
		}()
	}

	wg.Wait()
	assert.Equal(t, 0, len(broker.ActiveLeases()))
}
