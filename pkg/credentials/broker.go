package credentials

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"
)

// BrokerOption allows configuring broker TTL bounds
type BrokerOption func(*Broker)

// WithTTLBounds configures minimum and maximum allowed lease TTLs
func WithTTLBounds(min, max, def time.Duration) BrokerOption {
	return func(b *Broker) {
		if min > 0 {
			b.minTTL = min
		}
		if max > min {
			b.maxTTL = max
		}
		if def >= min && def <= max {
			b.defaultTTL = def
		}
	}
}

// Broker coordinates ephemeral credential issuance, automatic background revocation, and drivers
type Broker struct {
	mu         sync.RWMutex
	drivers    map[string]Driver
	leases     map[string]*Lease
	timers     map[string]*time.Timer
	minTTL     time.Duration
	maxTTL     time.Duration
	defaultTTL time.Duration
	closed     bool
}

// NewBroker initializes a dynamic credential broker
func NewBroker(opts ...BrokerOption) *Broker {
	b := &Broker{
		drivers:    make(map[string]Driver),
		leases:     make(map[string]*Lease),
		timers:     make(map[string]*time.Timer),
		minTTL:     5 * time.Second,
		maxTTL:     2 * time.Hour,
		defaultTTL: 15 * time.Minute,
	}

	for _, opt := range opts {
		opt(b)
	}

	// Register default generic token driver
	generic := NewGenericTokenDriver()
	b.RegisterDriver(generic.Name(), generic)

	return b
}

// RegisterDriver binds a credential driver to a target or protocol name
func (b *Broker) RegisterDriver(target string, driver Driver) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.drivers[target] = driver
}

// IssueLease requests dynamic credentials from the appropriate driver and schedules auto-revocation
func (b *Broker) IssueLease(ctx context.Context, req LeaseRequest) (*Lease, error) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, fmt.Errorf("credential broker is shut down")
	}

	if req.TTL <= 0 {
		req.TTL = b.defaultTTL
	}
	if req.TTL < b.minTTL || req.TTL > b.maxTTL {
		b.mu.Unlock()
		return nil, fmt.Errorf("%w: requested %v (allowed between %v and %v)", ErrInvalidTTL, req.TTL, b.minTTL, b.maxTTL)
	}

	driver, exists := b.drivers[req.Target]
	if !exists {
		driver = b.drivers["generic_token"]
		if driver == nil {
			b.mu.Unlock()
			return nil, fmt.Errorf("%w: '%s'", ErrDriverNotFound, req.Target)
		}
	}
	b.mu.Unlock()

	lease, err := driver.Generate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("driver '%s' failed to generate credentials: %w", driver.Name(), err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.leases[lease.ID] = lease

	// Schedule automated background revocation timer
	leaseID := lease.ID
	b.timers[leaseID] = time.AfterFunc(lease.TTL, func() {
		_ = b.RevokeLease(context.Background(), leaseID)
	})

	return lease.Clone(), nil
}

// RevokeLease immediately revokes credentials for the given lease and cancels its background timer
func (b *Broker) RevokeLease(ctx context.Context, leaseID string) error {
	b.mu.Lock()
	lease, exists := b.leases[leaseID]
	if !exists {
		b.mu.Unlock()
		return ErrLeaseNotFound
	}

	lease.mu.Lock()
	if lease.Revoked {
		lease.mu.Unlock()
		b.mu.Unlock()
		return nil
	}
	lease.mu.Unlock()

	// Stop timer if active
	if timer, ok := b.timers[leaseID]; ok {
		timer.Stop()
		delete(b.timers, leaseID)
	}

	driver := b.drivers[lease.Target]
	if driver == nil {
		driver = b.drivers["generic_token"]
	}
	b.mu.Unlock()

	var revokeErr error
	if driver != nil {
		revokeErr = driver.Revoke(ctx, lease)
	}

	lease.mu.Lock()
	now := time.Now()
	lease.Revoked = true
	lease.RevokedAt = &now
	lease.mu.Unlock()

	return revokeErr
}

// RenewLease extends the validity period of an active lease
func (b *Broker) RenewLease(ctx context.Context, leaseID string, extendTTL time.Duration) (*Lease, error) {
	b.mu.Lock()
	lease, exists := b.leases[leaseID]
	if !exists {
		b.mu.Unlock()
		return nil, ErrLeaseNotFound
	}

	lease.mu.RLock()
	if lease.Revoked {
		lease.mu.RUnlock()
		b.mu.Unlock()
		return nil, ErrLeaseExpired
	}
	lease.mu.RUnlock()

	if extendTTL <= 0 {
		extendTTL = b.defaultTTL
	}

	driver := b.drivers[lease.Target]
	if driver == nil {
		driver = b.drivers["generic_token"]
	}
	b.mu.Unlock()

	renewed, err := driver.Renew(ctx, lease, extendTTL)
	if err != nil {
		return nil, fmt.Errorf("driver failed to renew lease '%s': %w", leaseID, err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Reset timer
	if timer, ok := b.timers[leaseID]; ok {
		timer.Stop()
	}
	remaining := time.Until(renewed.ExpiresAt)
	b.timers[leaseID] = time.AfterFunc(remaining, func() {
		_ = b.RevokeLease(context.Background(), leaseID)
	})

	b.leases[leaseID] = renewed
	return renewed.Clone(), nil
}

// GetLease returns a cloned lease by its ID
func (b *Broker) GetLease(leaseID string) (*Lease, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	lease, exists := b.leases[leaseID]
	if !exists {
		return nil, ErrLeaseNotFound
	}
	return lease.Clone(), nil
}

// ActiveLeases returns all currently valid, non-revoked leases as clones
func (b *Broker) ActiveLeases() []*Lease {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var active []*Lease
	for _, l := range b.leases {
		if !l.IsExpired() {
			active = append(active, l.Clone())
		}
	}
	return active
}

// Shutdown stops all background timers and revokes all currently active leases
func (b *Broker) Shutdown(ctx context.Context) error {
	b.mu.Lock()
	b.closed = true
	var activeIDs []string
	for id, timer := range b.timers {
		timer.Stop()
		activeIDs = append(activeIDs, id)
	}
	b.timers = make(map[string]*time.Timer)
	b.mu.Unlock()

	for _, id := range activeIDs {
		_ = b.RevokeLease(ctx, id)
	}

	return nil
}

// GenericTokenDriver creates high-entropy temporary API tokens
type GenericTokenDriver struct {
	mu           sync.RWMutex
	activeTokens map[string]*Lease
}

// NewGenericTokenDriver creates an in-memory token driver
func NewGenericTokenDriver() *GenericTokenDriver {
	return &GenericTokenDriver{
		activeTokens: make(map[string]*Lease),
	}
}

func (d *GenericTokenDriver) Name() string {
	return "generic_token"
}

func (d *GenericTokenDriver) Generate(ctx context.Context, req LeaseRequest) (*Lease, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random token: %w", err)
	}

	token := "krypton_tok_" + hex.EncodeToString(tokenBytes)
	leaseID := GenerateLeaseID("tok")
	now := time.Now()

	lease := &Lease{
		ID:          leaseID,
		Target:      req.Target,
		Type:        TypeAPIToken,
		Token:       token,
		IssuedAt:    now,
		ExpiresAt:   now.Add(req.TTL),
		TTL:         req.TTL,
		Permissions: req.Permissions,
		Metadata:    req.Metadata,
		Revoked:     false,
	}

	d.activeTokens[leaseID] = lease
	return lease, nil
}

func (d *GenericTokenDriver) Revoke(ctx context.Context, lease *Lease) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.activeTokens, lease.ID)
	return nil
}

func (d *GenericTokenDriver) Renew(ctx context.Context, lease *Lease, extendTTL time.Duration) (*Lease, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.activeTokens[lease.ID]; !exists {
		return nil, ErrLeaseNotFound
	}

	now := time.Now()
	lease.ExpiresAt = now.Add(extendTTL)
	lease.TTL = extendTTL

	return lease, nil
}
