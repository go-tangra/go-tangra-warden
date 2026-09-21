package cache

import (
	"context"
	"testing"
	"time"
)

func TestMemoryCounters(t *testing.T) {
	m := NewMemory()
	now := time.Unix(1000, 0)
	m.Now = func() time.Time { return now }
	c := New(m)
	defer c.Close()
	ctx := context.Background()
	k := RateKey("open", "203.0.113.9")
	for i := 1; i <= 3; i++ {
		if n, err := c.Count(ctx, k, time.Minute); err != nil || n != int64(i) {
			t.Fatalf("%d: %d %v", i, n, err)
		}
	}
	if c.Limited(ctx, k, 3, time.Minute) != true || c.Limited(ctx, k, 0, time.Minute) {
		t.Fatal("limit")
	}
	var nilCache *Cache
	if nilCache.Limited(ctx, k, 1, time.Minute) {
		t.Fatal("nil cache limits")
	}
	now = now.Add(2 * time.Minute)
	if n, _ := c.Count(ctx, k, time.Minute); n != 1 {
		t.Fatalf("window did not expire: %d", n)
	}
	if n, _ := c.Count(ctx, "forever", 0); n != 1 {
		t.Fatalf("no ttl: %d", n)
	}
	if String(7) != "7" {
		t.Fatal("String")
	}
}

func TestValkeyConfig(t *testing.T) {
	if _, err := NewValkey(ValkeyConfig{}); err == nil {
		t.Fatal("no addresses accepted")
	}
	if _, err := NewValkey(ValkeyConfig{Addresses: []string{"127.0.0.1:1"}, CAPEM: []byte("junk")}); err == nil {
		t.Fatal("bad CA accepted")
	}
	// A TLS client to a closed port fails to connect.
	if _, err := NewValkey(ValkeyConfig{Addresses: []string{"127.0.0.1:1"}}); err == nil {
		t.Fatal("expected connection error")
	}
}
