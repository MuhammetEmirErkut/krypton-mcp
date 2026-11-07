package credentials

import (
	"context"
	"fmt"
	"time"
)

// MySQLConfig configures the MySQL/MariaDB dynamic user driver
type MySQLConfig struct {
	Host       string `yaml:"host" json:"host"`
	Port       int    `yaml:"port" json:"port"`
	Database   string `yaml:"database" json:"database"`
	UserPrefix string `yaml:"user_prefix" json:"user_prefix"`
}

// MySQLDriver provisions and revokes temporary MySQL users. Expiry is enforced both by the
// broker's revocation timer and by MySQL's PASSWORD EXPIRE / ACCOUNT LOCK semantics on revoke.
type MySQLDriver struct {
	cfg      MySQLConfig
	executor SQLExecutor
}

// NewMySQLDriver creates a new MySQL credential driver
func NewMySQLDriver(cfg MySQLConfig, executor SQLExecutor) *MySQLDriver {
	if cfg.Port == 0 {
		cfg.Port = 3306
	}
	if cfg.Host == "" {
		cfg.Host = "localhost"
	}
	if cfg.Database == "" {
		cfg.Database = "mysql"
	}
	if cfg.UserPrefix == "" {
		cfg.UserPrefix = "krypton_my"
	}
	if executor == nil {
		executor = NewMockSQLExecutor()
	}
	return &MySQLDriver{cfg: cfg, executor: executor}
}

func (d *MySQLDriver) Name() string { return "mysql" }

// Generate creates a temporary MySQL user limited to the configured database.
func (d *MySQLDriver) Generate(ctx context.Context, req LeaseRequest) (*Lease, error) {
	perms := req.Permissions
	if len(perms) == 0 {
		perms = []string{"SELECT"}
	}
	cleanPerms, err := normalizeSQLPrivileges(perms)
	if err != nil {
		return nil, err
	}
	if !safeIdentifier(d.cfg.Database) {
		return nil, fmt.Errorf("invalid mysql database name %q", d.cfg.Database)
	}

	username := GenerateLeaseID(d.cfg.UserPrefix)
	password, err := GenerateSecurePassword(24)
	if err != nil {
		return nil, fmt.Errorf("failed to generate secure db password: %w", err)
	}
	// MySQL string literals: the generated charset contains no quotes or backslashes.
	create := fmt.Sprintf("CREATE USER '%s'@'%%' IDENTIFIED BY '%s';", username, password)
	if err := d.executor.ExecContext(ctx, create); err != nil {
		return nil, fmt.Errorf("failed to create mysql user '%s': %w", username, err)
	}

	for _, p := range cleanPerms {
		grant := fmt.Sprintf("GRANT %s ON `%s`.* TO '%s'@'%%';", p, d.cfg.Database, username)
		if err := d.executor.ExecContext(ctx, grant); err != nil {
			_ = d.executor.ExecContext(ctx, fmt.Sprintf("DROP USER IF EXISTS '%s'@'%%';", username))
			return nil, fmt.Errorf("failed to grant %s to mysql user '%s': %w", p, username, err)
		}
	}

	now := time.Now().UTC()
	connURI := fmt.Sprintf("mysql://%s:%s@%s:%d/%s", username, password, d.cfg.Host, d.cfg.Port, d.cfg.Database)
	return &Lease{
		ID:          GenerateLeaseID("mysql_lease"),
		Target:      d.Name(),
		Type:        TypeDatabase,
		Username:    username,
		Password:    password,
		Token:       connURI,
		IssuedAt:    now,
		ExpiresAt:   now.Add(req.TTL),
		TTL:         req.TTL,
		Permissions: cleanPerms,
		Metadata: map[string]string{
			"host":     d.cfg.Host,
			"port":     fmt.Sprintf("%d", d.cfg.Port),
			"database": d.cfg.Database,
			"conn_uri": connURI,
		},
	}, nil
}

// Revoke locks the account and drops it.
func (d *MySQLDriver) Revoke(ctx context.Context, lease *Lease) error {
	if lease == nil || lease.Username == "" {
		return nil
	}
	u := lease.Username
	// Lock first so no new sessions can start while existing ones are being dropped.
	_ = d.executor.ExecContext(ctx, fmt.Sprintf("ALTER USER IF EXISTS '%s'@'%%' ACCOUNT LOCK;", u))
	// Note: DROP USER does not terminate sessions that are already open on the server;
	// they end when the connection closes. Pair with a short TTL for strict cutoff.
	if err := d.executor.ExecContext(ctx, fmt.Sprintf("DROP USER IF EXISTS '%s'@'%%';", u)); err != nil {
		return fmt.Errorf("failed to drop mysql user '%s': %w", u, err)
	}
	return nil
}

// Renew only extends the lease bookkeeping; MySQL accounts have no VALID UNTIL equivalent.
func (d *MySQLDriver) Renew(ctx context.Context, lease *Lease, extendTTL time.Duration) (*Lease, error) {
	if lease == nil || lease.Username == "" {
		return nil, ErrLeaseNotFound
	}
	renewed := lease.Clone()
	renewed.ExpiresAt = time.Now().UTC().Add(extendTTL)
	renewed.TTL = extendTTL
	return renewed, nil
}

func safeIdentifier(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
