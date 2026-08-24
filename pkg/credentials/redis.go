package credentials

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// RedisCommandExecutor executes Redis commands
type RedisCommandExecutor interface {
	Do(ctx context.Context, cmd string, args ...any) error
}

// MockRedisExecutor records executed commands for testing
type MockRedisExecutor struct {
	mu       sync.Mutex
	Commands [][]any
}

// NewMockRedisExecutor creates a test Redis command executor
func NewMockRedisExecutor() *MockRedisExecutor {
	return &MockRedisExecutor{Commands: make([][]any, 0)}
}

// Do records command and arguments
func (m *MockRedisExecutor) Do(ctx context.Context, cmd string, args ...any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := []any{cmd}
	entry = append(entry, args...)
	m.Commands = append(m.Commands, entry)
	return nil
}

// RedisConfig configures the dynamic Redis ACL driver
type RedisConfig struct {
	Addr       string `yaml:"addr" json:"addr"`
	UserPrefix string `yaml:"user_prefix" json:"user_prefix"`
	KeyPattern string `yaml:"key_pattern" json:"key_pattern"`
}

// RedisDriver dynamically provisions and revokes temporary Redis ACL users
type RedisDriver struct {
	cfg      RedisConfig
	executor RedisCommandExecutor
}

// NewRedisDriver creates a new Redis credential driver
func NewRedisDriver(cfg RedisConfig, executor RedisCommandExecutor) *RedisDriver {
	if cfg.Addr == "" {
		cfg.Addr = "localhost:6379"
	}
	if cfg.UserPrefix == "" {
		cfg.UserPrefix = "krypton_redis"
	}
	if cfg.KeyPattern == "" {
		cfg.KeyPattern = "*"
	}
	if executor == nil {
		executor = NewMockRedisExecutor()
	}

	return &RedisDriver{
		cfg:      cfg,
		executor: executor,
	}
}

func (d *RedisDriver) Name() string {
	return "redis"
}

// Generate creates a temporary Redis user with ACL rules and a strong password
func (d *RedisDriver) Generate(ctx context.Context, req LeaseRequest) (*Lease, error) {
	username := GenerateLeaseID(d.cfg.UserPrefix)
	password, err := GenerateSecurePassword(24)
	if err != nil {
		return nil, fmt.Errorf("failed to generate secure redis password: %w", err)
	}

	keyPattern := d.cfg.KeyPattern
	if kp, ok := req.Metadata["key_pattern"]; ok && kp != "" {
		keyPattern = kp
	}

	// Default to read-only permissions if not specified
	perms := req.Permissions
	if len(perms) == 0 {
		perms = []string{"+@read", "-@write", "-@admin", "-@dangerous"}
	}

	// Build ACL SETUSER arguments: username on >password ~keypattern perms...
	args := []any{
		username,
		"on",
		">" + password,
		"~" + keyPattern,
	}
	for _, p := range perms {
		args = append(args, strings.TrimSpace(p))
	}

	if err := d.executor.Do(ctx, "ACL", append([]any{"SETUSER"}, args...)...); err != nil {
		return nil, fmt.Errorf("failed to create redis ACL user '%s': %w", username, err)
	}

	connURI := fmt.Sprintf("redis://%s:%s@%s", username, password, d.cfg.Addr)
	leaseID := GenerateLeaseID("redis_lease")
	now := time.Now().UTC()

	return &Lease{
		ID:          leaseID,
		Target:      d.Name(),
		Type:        TypeDatabase,
		Username:    username,
		Password:    password,
		Token:       connURI,
		IssuedAt:    now,
		ExpiresAt:   now.Add(req.TTL),
		TTL:         req.TTL,
		Permissions: perms,
		Metadata: map[string]string{
			"addr":        d.cfg.Addr,
			"conn_uri":    connURI,
			"key_pattern": keyPattern,
		},
		Revoked: false,
	}, nil
}

// Revoke deletes the temporary ACL user and closes active client connections
func (d *RedisDriver) Revoke(ctx context.Context, lease *Lease) error {
	if lease == nil || lease.Username == "" {
		return nil
	}

	username := lease.Username

	// 1. Terminate all active client connections for this user
	_ = d.executor.Do(ctx, "CLIENT", "KILL", "USER", username)

	// 2. Delete the ACL user
	if err := d.executor.Do(ctx, "ACL", "DELUSER", username); err != nil {
		return fmt.Errorf("failed to delete redis ACL user '%s': %w", username, err)
	}

	return nil
}

// Renew extends the lease time for the Redis user
func (d *RedisDriver) Renew(ctx context.Context, lease *Lease, extendTTL time.Duration) (*Lease, error) {
	if lease == nil || lease.Username == "" {
		return nil, ErrLeaseNotFound
	}

	renewed := lease.Clone()
	renewed.ExpiresAt = time.Now().UTC().Add(extendTTL)
	renewed.TTL = extendTTL
	return renewed, nil
}
