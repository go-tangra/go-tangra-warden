// Package cache holds the short-lived counters warden keeps in Valkey: rate
// limits for share opens and lookups. Nothing secret is ever cached.
package cache

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	valkey "github.com/valkey-io/valkey-go"
)

// KV is the counter store (Valkey in production, Memory in tests).
type KV interface {
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)
	Close()
}

// RateKey names a rate-limit window.
func RateKey(kind, subject string) string { return "warden:rl:" + kind + ":" + subject }

// Cache counts events per window.
type Cache struct{ kv KV }

// New wraps a KV.
func New(kv KV) *Cache { return &Cache{kv: kv} }

// Close releases the KV.
func (c *Cache) Close() { c.kv.Close() }

// Count increments key and returns the count in the window.
func (c *Cache) Count(ctx context.Context, key string, window time.Duration) (int64, error) {
	return c.kv.Incr(ctx, key, window)
}

// Limited reports whether key exceeded limit within window (limit ≤ 0 = never).
func (c *Cache) Limited(ctx context.Context, key string, limit int, window time.Duration) bool {
	if c == nil || limit <= 0 {
		return false
	}
	n, err := c.kv.Incr(ctx, key, window)
	return err == nil && n > int64(limit)
}

// Memory is an in-process KV.
type Memory struct {
	mu   sync.Mutex
	data map[string]entry
	Now  func() time.Time
}

type entry struct {
	n   int64
	exp time.Time
}

// NewMemory returns an empty in-process KV.
func NewMemory() *Memory { return &Memory{data: map[string]entry{}, Now: time.Now} }

// Incr implements KV.
func (m *Memory) Incr(_ context.Context, key string, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.data[key]
	if ok && !e.exp.IsZero() && !m.Now().Before(e.exp) {
		ok = false
	}
	if !ok {
		e = entry{}
		if ttl > 0 {
			e.exp = m.Now().Add(ttl)
		}
	}
	e.n++
	m.data[key] = e
	return e.n, nil
}

// Close implements KV.
func (m *Memory) Close() {}

// ValkeyConfig connects to Valkey. TLS is required unless AllowPlaintext.
type ValkeyConfig struct {
	Addresses      []string
	Username       string
	Password       string
	AllowPlaintext bool
	CAPEM          []byte
}

type valkeyKV struct{ c valkey.Client }

// NewValkey returns a KV backed by Valkey (TLS 1.3 enforced when TLS is used).
func NewValkey(cfg ValkeyConfig) (KV, error) {
	if len(cfg.Addresses) == 0 {
		return nil, errors.New("cache: valkey addresses required")
	}
	opt := valkey.ClientOption{InitAddress: cfg.Addresses, Username: cfg.Username, Password: cfg.Password}
	if !cfg.AllowPlaintext {
		opt.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		if len(cfg.CAPEM) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(cfg.CAPEM) {
				return nil, errors.New("cache: valkey ca is not valid PEM")
			}
			opt.TLSConfig.RootCAs = pool
		}
	}
	c, err := valkey.NewClient(opt)
	if err != nil {
		return nil, fmt.Errorf("cache: %w", err)
	}
	return &valkeyKV{c: c}, nil
}

func (v *valkeyKV) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	n, err := v.c.Do(ctx, v.c.B().Incr().Key(key).Build()).AsInt64()
	if err != nil {
		return 0, err
	}
	if n == 1 && ttl > 0 {
		_ = v.c.Do(ctx, v.c.B().Pexpire().Key(key).Milliseconds(ttl.Milliseconds()).Build()).Error()
	}
	return n, nil
}

func (v *valkeyKV) Close() { v.c.Close() }

// String formats a counter (test helper).
func String(n int64) string { return strconv.FormatInt(n, 10) }
