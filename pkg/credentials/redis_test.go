package credentials

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedisDriver_GenerateAndRevoke(t *testing.T) {
	mockRedis := NewMockRedisExecutor()
	driver := NewRedisDriver(RedisConfig{
		Addr:       "redis.internal:6379",
		UserPrefix: "krypton_cache",
		KeyPattern: "session:*",
	}, mockRedis)

	req := LeaseRequest{
		Target:      "redis",
		Type:        TypeDatabase,
		TTL:         15 * time.Minute,
		Permissions: []string{"+@read", "+@write"},
	}

	// 1. Generate ACL user
	lease, err := driver.Generate(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, lease)
	assert.Equal(t, "redis", lease.Target)
	assert.NotEmpty(t, lease.Username)
	assert.NotEmpty(t, lease.Password)
	assert.Contains(t, lease.Token, "redis://krypton_cache_")
	assert.Contains(t, lease.Token, "@redis.internal:6379")

	// Verify command executed
	require.Len(t, mockRedis.Commands, 1)
	cmd := mockRedis.Commands[0]
	assert.Equal(t, "ACL", cmd[0])
	assert.Equal(t, "SETUSER", cmd[1])
	assert.Equal(t, lease.Username, cmd[2])
	assert.Equal(t, "on", cmd[3])
	assert.Equal(t, ">"+lease.Password, cmd[4])
	assert.Equal(t, "~session:*", cmd[5])
	assert.Equal(t, "+@read", cmd[6])
	assert.Equal(t, "+@write", cmd[7])

	// 2. Revoke ACL user
	mockRedis.Commands = nil
	err = driver.Revoke(context.Background(), lease)
	require.NoError(t, err)

	require.Len(t, mockRedis.Commands, 2)
	assert.Equal(t, []any{"CLIENT", "KILL", "USER", lease.Username}, mockRedis.Commands[0])
	assert.Equal(t, []any{"ACL", "DELUSER", lease.Username}, mockRedis.Commands[1])
}
