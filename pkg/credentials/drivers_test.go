package credentials

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostgresRejectsInjectedPermissions(t *testing.T) {
	exec := NewMockSQLExecutor()
	d := NewPostgresDriver(PostgresConfig{}, exec)
	for _, bad := range []string{
		"SELECT ON ALL TABLES IN SCHEMA public TO postgres; DROP TABLE users; --",
		"ALL PRIVILEGES", "SELECT;", "",
	} {
		_, err := d.Generate(context.Background(), LeaseRequest{TTL: time.Minute, Permissions: []string{bad}})
		require.Error(t, err, bad)
		assert.True(t, errors.Is(err, ErrInvalidPermission), bad)
	}
	assert.Empty(t, exec.Queries, "nothing may reach the database when validation fails")
}

type failingGrantExec struct{ MockSQLExecutor }

func (f *failingGrantExec) ExecContext(ctx context.Context, q string, a ...any) error {
	_ = f.MockSQLExecutor.ExecContext(ctx, q, a...)
	if strings.HasPrefix(q, "GRANT") {
		return errors.New("boom")
	}
	return nil
}

func TestPostgresGrantFailureRollsBackRole(t *testing.T) {
	exec := &failingGrantExec{}
	d := NewPostgresDriver(PostgresConfig{}, exec)
	_, err := d.Generate(context.Background(), LeaseRequest{TTL: time.Minute})
	require.Error(t, err)
	assert.Contains(t, exec.Queries[len(exec.Queries)-1], "DROP ROLE")
}

func TestRedisRejectsEscalation(t *testing.T) {
	d := NewRedisDriver(RedisConfig{}, NewMockRedisExecutor())
	for _, rules := range [][]string{{"+@all"}, {"allkeys"}, {"on"}, {"nopass"}, {">pw"}, {"~*"}, {"+@admin"}} {
		_, err := d.Generate(context.Background(), LeaseRequest{TTL: time.Minute, Permissions: rules})
		assert.True(t, errors.Is(err, ErrInvalidPermission), "%v", rules)
	}
	_, err := d.Generate(context.Background(), LeaseRequest{TTL: time.Minute, Metadata: map[string]string{"key_pattern": "* ~* +@all"}})
	assert.True(t, errors.Is(err, ErrInvalidPermission))

	l, err := d.Generate(context.Background(), LeaseRequest{TTL: time.Minute, Permissions: []string{"+@read"}, Metadata: map[string]string{"key_pattern": "app:*"}})
	require.NoError(t, err)
	assert.Equal(t, "app:*", l.Metadata["key_pattern"])
}

func TestMySQLLifecycle(t *testing.T) {
	exec := NewMockSQLExecutor()
	d := NewMySQLDriver(MySQLConfig{Database: "shop"}, exec)
	l, err := d.Generate(context.Background(), LeaseRequest{TTL: time.Minute, Permissions: []string{"select", "insert"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"SELECT", "INSERT"}, l.Permissions)
	assert.Contains(t, exec.Queries[0], "CREATE USER")
	assert.Contains(t, exec.Queries[1], "GRANT SELECT ON `shop`.*")

	require.NoError(t, d.Revoke(context.Background(), l))
	assert.Contains(t, exec.Queries[len(exec.Queries)-1], "DROP USER")

	_, err = d.Generate(context.Background(), LeaseRequest{TTL: time.Minute, Permissions: []string{"ALL"}})
	assert.True(t, errors.Is(err, ErrInvalidPermission))
	_, err = NewMySQLDriver(MySQLConfig{Database: "a`; DROP"}, exec).Generate(context.Background(), LeaseRequest{TTL: time.Minute})
	assert.Error(t, err)
}
