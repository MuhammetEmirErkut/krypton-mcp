package credentials

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// SQLExecutor executes raw database statements (can be backed by *sql.DB or a mock)
type SQLExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) error
}

// MockSQLExecutor records executed SQL queries for testing
type MockSQLExecutor struct {
	mu      sync.Mutex
	Queries []string
}

// NewMockSQLExecutor creates a test SQL executor
func NewMockSQLExecutor() *MockSQLExecutor {
	return &MockSQLExecutor{Queries: make([]string, 0)}
}

// ExecContext records the query string
func (m *MockSQLExecutor) ExecContext(ctx context.Context, query string, args ...any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Queries = append(m.Queries, query)
	return nil
}

// PostgresConfig configures the PostgreSQL dynamic role driver
type PostgresConfig struct {
	Host       string `yaml:"host" json:"host"`
	Port       int    `yaml:"port" json:"port"`
	Database   string `yaml:"database" json:"database"`
	RolePrefix string `yaml:"role_prefix" json:"role_prefix"`
	DefaultTTL time.Duration
}

// PostgresDriver provisions and revokes temporary PostgreSQL roles with strict expiration
type PostgresDriver struct {
	cfg      PostgresConfig
	executor SQLExecutor
}

// NewPostgresDriver creates a new Postgres credential driver
func NewPostgresDriver(cfg PostgresConfig, executor SQLExecutor) *PostgresDriver {
	if cfg.Port == 0 {
		cfg.Port = 5432
	}
	if cfg.Host == "" {
		cfg.Host = "localhost"
	}
	if cfg.Database == "" {
		cfg.Database = "postgres"
	}
	if cfg.RolePrefix == "" {
		cfg.RolePrefix = "krypton_pg"
	}
	if executor == nil {
		executor = NewMockSQLExecutor()
	}

	return &PostgresDriver{
		cfg:      cfg,
		executor: executor,
	}
}

func (d *PostgresDriver) Name() string {
	return "postgres"
}

// Generate creates a temporary PostgreSQL user with a strong password and VALID UNTIL timestamp
func (d *PostgresDriver) Generate(ctx context.Context, req LeaseRequest) (*Lease, error) {
	username := GenerateLeaseID(d.cfg.RolePrefix)
	password, err := GenerateSecurePassword(24)
	if err != nil {
		return nil, fmt.Errorf("failed to generate secure db password: %w", err)
	}

	now := time.Now().UTC()
	expiresAt := now.Add(req.TTL)
	validUntilStr := expiresAt.Format("2006-01-02 15:04:05-07")

	// 1. Create temporary role with login and expiration
	createRoleQuery := fmt.Sprintf(`CREATE ROLE "%s" WITH LOGIN PASSWORD '%s' VALID UNTIL '%s';`,
		username, password, validUntilStr)
	if err := d.executor.ExecContext(ctx, createRoleQuery); err != nil {
		return nil, fmt.Errorf("failed to create postgres role '%s': %w", username, err)
	}

	// 2. Apply requested permissions (defaulting to read-only on public schema)
	perms := req.Permissions
	if len(perms) == 0 {
		perms = []string{"SELECT"}
	}

	for _, perm := range perms {
		permClean := strings.ToUpper(strings.TrimSpace(perm))
		grantQuery := fmt.Sprintf(`GRANT %s ON ALL TABLES IN SCHEMA public TO "%s";`, permClean, username)
		_ = d.executor.ExecContext(ctx, grantQuery)
	}

	connURI := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		username, password, d.cfg.Host, d.cfg.Port, d.cfg.Database)

	leaseID := GenerateLeaseID("pg_lease")
	return &Lease{
		ID:          leaseID,
		Target:      d.Name(),
		Type:        TypeDatabase,
		Username:    username,
		Password:    password,
		Token:       connURI,
		IssuedAt:    now,
		ExpiresAt:   expiresAt,
		TTL:         req.TTL,
		Permissions: perms,
		Metadata: map[string]string{
			"host":     d.cfg.Host,
			"port":     fmt.Sprintf("%d", d.cfg.Port),
			"database": d.cfg.Database,
			"conn_uri": connURI,
		},
		Revoked: false,
	}, nil
}

// Revoke terminates active sessions and drops the temporary role
func (d *PostgresDriver) Revoke(ctx context.Context, lease *Lease) error {
	if lease == nil || lease.Username == "" {
		return nil
	}

	username := lease.Username

	// 1. Terminate all active backend connections for this role
	terminateQuery := fmt.Sprintf(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '%s';`, username)
	_ = d.executor.ExecContext(ctx, terminateQuery)

	// 2. Reassign / drop owned objects if any
	dropOwnedQuery := fmt.Sprintf(`DROP OWNED BY "%s" CASCADE;`, username)
	_ = d.executor.ExecContext(ctx, dropOwnedQuery)

	// 3. Drop role
	dropRoleQuery := fmt.Sprintf(`DROP ROLE IF EXISTS "%s";`, username)
	if err := d.executor.ExecContext(ctx, dropRoleQuery); err != nil {
		return fmt.Errorf("failed to drop postgres role '%s': %w", username, err)
	}

	return nil
}

// Renew extends the VALID UNTIL timestamp of the database role
func (d *PostgresDriver) Renew(ctx context.Context, lease *Lease, extendTTL time.Duration) (*Lease, error) {
	if lease == nil || lease.Username == "" {
		return nil, ErrLeaseNotFound
	}

	now := time.Now().UTC()
	newExpiresAt := now.Add(extendTTL)
	validUntilStr := newExpiresAt.Format("2006-01-02 15:04:05-07")

	alterQuery := fmt.Sprintf(`ALTER ROLE "%s" VALID UNTIL '%s';`, lease.Username, validUntilStr)
	if err := d.executor.ExecContext(ctx, alterQuery); err != nil {
		return nil, fmt.Errorf("failed to extend postgres role '%s': %w", lease.Username, err)
	}

	renewed := lease.Clone()
	renewed.ExpiresAt = newExpiresAt
	renewed.TTL = extendTTL
	return renewed, nil
}
