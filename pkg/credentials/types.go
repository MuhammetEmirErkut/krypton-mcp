package credentials

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"
)

// CredentialType classifies the category of ephemeral credentials
type CredentialType string

const (
	TypeDatabase CredentialType = "database"
	TypeAPIToken CredentialType = "api_token"
	TypeIAMRole  CredentialType = "iam_role"
	TypeCustom   CredentialType = "custom"
)

var (
	ErrLeaseNotFound  = errors.New("credential lease not found")
	ErrLeaseExpired   = errors.New("credential lease has expired")
	ErrDriverNotFound = errors.New("credential driver not registered for target")
	ErrInvalidTTL     = errors.New("requested TTL is outside allowed bounds")
)

// Lease represents a short-lived, Just-In-Time credential lease
type Lease struct {
	mu          sync.RWMutex
	ID          string            `json:"id"`
	Target      string            `json:"target"`
	Type        CredentialType    `json:"type"`
	Username    string            `json:"username,omitempty"`
	Password    string            `json:"password,omitempty"`
	Token       string            `json:"token,omitempty"`
	IssuedAt    time.Time         `json:"issued_at"`
	ExpiresAt   time.Time         `json:"expires_at"`
	TTL         time.Duration     `json:"ttl"`
	Permissions []string          `json:"permissions,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Revoked     bool              `json:"revoked"`
	RevokedAt   *time.Time        `json:"revoked_at,omitempty"`
}

// Clone creates a thread-safe deep copy of the Lease
func (l *Lease) Clone() *Lease {
	l.mu.RLock()
	defer l.mu.RUnlock()

	perms := make([]string, len(l.Permissions))
	copy(perms, l.Permissions)

	meta := make(map[string]string, len(l.Metadata))
	for k, v := range l.Metadata {
		meta[k] = v
	}

	var revAt *time.Time
	if l.RevokedAt != nil {
		t := *l.RevokedAt
		revAt = &t
	}

	return &Lease{
		ID:          l.ID,
		Target:      l.Target,
		Type:        l.Type,
		Username:    l.Username,
		Password:    l.Password,
		Token:       l.Token,
		IssuedAt:    l.IssuedAt,
		ExpiresAt:   l.ExpiresAt,
		TTL:         l.TTL,
		Permissions: perms,
		Metadata:    meta,
		Revoked:     l.Revoked,
		RevokedAt:   revAt,
	}
}

// IsExpired checks if the lease has passed its expiration deadline
func (l *Lease) IsExpired() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.Revoked || time.Now().After(l.ExpiresAt)
}

// LeaseRequest defines constraints when requesting a dynamic credential
type LeaseRequest struct {
	Target      string            `json:"target"`
	Type        CredentialType    `json:"type"`
	TTL         time.Duration     `json:"ttl"`
	Permissions []string          `json:"permissions,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Driver defines the lifecycle contract for backend credential providers (Postgres, Redis, AWS, etc.)
type Driver interface {
	Name() string
	Generate(ctx context.Context, req LeaseRequest) (*Lease, error)
	Revoke(ctx context.Context, lease *Lease) error
	Renew(ctx context.Context, lease *Lease, extendTTL time.Duration) (*Lease, error)
}

// GenerateSecurePassword produces a cryptographically random, high-entropy password
func GenerateSecurePassword(length int) (string, error) {
	if length < 16 {
		length = 24
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
	bytes := make([]byte, length)

	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random character: %w", err)
		}
		bytes[i] = charset[num.Int64()]
	}

	return string(bytes), nil
}

// GenerateLeaseID creates a unique, prefixed identifier for a credential lease
func GenerateLeaseID(prefix string) string {
	bytes := make([]byte, 8)
	_, _ = io.ReadFull(rand.Reader, bytes)
	if prefix == "" {
		prefix = "lease"
	}
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(bytes))
}
