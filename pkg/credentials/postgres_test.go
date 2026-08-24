package credentials

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostgresDriver_GenerateAndRevoke(t *testing.T) {
	mockSQL := NewMockSQLExecutor()
	driver := NewPostgresDriver(PostgresConfig{
		Host:       "pg.internal",
		Port:       5432,
		Database:   "analytics",
		RolePrefix: "krypton_app",
	}, mockSQL)

	req := LeaseRequest{
		Target:      "postgres",
		Type:        TypeDatabase,
		TTL:         10 * time.Minute,
		Permissions: []string{"SELECT", "INSERT"},
	}

	// 1. Generate role
	lease, err := driver.Generate(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, lease)
	assert.Equal(t, "postgres", lease.Target)
	assert.NotEmpty(t, lease.Username)
	assert.NotEmpty(t, lease.Password)
	assert.Contains(t, lease.Token, "postgres://krypton_app_")
	assert.Contains(t, lease.Token, "@pg.internal:5432/analytics")

	// Verify queries
	require.Len(t, mockSQL.Queries, 3)
	assert.True(t, strings.HasPrefix(mockSQL.Queries[0], `CREATE ROLE "`+lease.Username+`" WITH LOGIN PASSWORD`))
	assert.Contains(t, mockSQL.Queries[0], "VALID UNTIL")
	assert.Equal(t, `GRANT SELECT ON ALL TABLES IN SCHEMA public TO "`+lease.Username+`";`, mockSQL.Queries[1])
	assert.Equal(t, `GRANT INSERT ON ALL TABLES IN SCHEMA public TO "`+lease.Username+`";`, mockSQL.Queries[2])

	// 2. Renew role
	mockSQL.Queries = nil
	renewed, err := driver.Renew(context.Background(), lease, 20*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 20*time.Minute, renewed.TTL)
	require.Len(t, mockSQL.Queries, 1)
	assert.True(t, strings.HasPrefix(mockSQL.Queries[0], `ALTER ROLE "`+lease.Username+`" VALID UNTIL`))

	// 3. Revoke role
	mockSQL.Queries = nil
	err = driver.Revoke(context.Background(), lease)
	require.NoError(t, err)

	require.Len(t, mockSQL.Queries, 3)
	assert.Contains(t, mockSQL.Queries[0], "pg_terminate_backend")
	assert.Contains(t, mockSQL.Queries[1], `DROP OWNED BY "`+lease.Username+`" CASCADE`)
	assert.Contains(t, mockSQL.Queries[2], `DROP ROLE IF EXISTS "`+lease.Username+`"`)
}
