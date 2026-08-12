// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package probe

import (
	"context"
	"sync"
	"testing"
	"time"
)

// newTestCache builds a Cache with a controllable clock and a counting probe
// runner, and no background goroutine.
func newTestCache(now *time.Time, calls *int) *Cache {
	var mu sync.Mutex
	return &Cache{
		entries: make(map[string]*cacheEntry),
		stop:    make(chan struct{}),
		now:     func() time.Time { return *now },
		run: func(_ context.Context, opt Options) map[string]Result {
			mu.Lock()
			*calls++
			mu.Unlock()
			return map[string]Result{
				"p2p": {Name: "p2p", OK: true, Host: opt.Host},
			}
		},
	}
}

func TestCacheSecondRequestIsServedFromCache(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	calls := 0
	c := newTestCache(&now, &calls)
	opt := Options{Host: "miner.example.com", APIPort: 20049}

	first := c.Get(context.Background(), opt)
	if first.Cached {
		t.Error("first request: got cached=true, want false")
	}
	if calls != 1 {
		t.Fatalf("first request: probe ran %d times, want 1", calls)
	}

	now = now.Add(time.Hour)
	second := c.Get(context.Background(), opt)
	if !second.Cached {
		t.Error("second request: got cached=false, want true")
	}
	if calls != 1 {
		t.Errorf("second request: probe ran %d times total, want 1", calls)
	}
	if !second.CachedAt.Equal(first.CachedAt) {
		t.Errorf("cached_at = %v, want the original %v", second.CachedAt, first.CachedAt)
	}
	if want := first.CachedAt.Add(CacheTTL); !second.ExpiresAt.Equal(want) {
		t.Errorf("expires_at = %v, want %v", second.ExpiresAt, want)
	}
}

func TestCacheReprobesAfterTTL(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	calls := 0
	c := newTestCache(&now, &calls)
	opt := Options{Host: "miner.example.com"}

	c.Get(context.Background(), opt)

	// One second short of a day is still a hit.
	now = now.Add(CacheTTL - time.Second)
	if resp := c.Get(context.Background(), opt); !resp.Cached {
		t.Error("just before TTL: got cached=false, want true")
	}
	if calls != 1 {
		t.Errorf("just before TTL: probe ran %d times, want 1", calls)
	}

	// Exactly at the TTL boundary the entry is stale.
	now = now.Add(time.Second)
	resp := c.Get(context.Background(), opt)
	if resp.Cached {
		t.Error("at TTL: got cached=true, want false")
	}
	if calls != 2 {
		t.Errorf("at TTL: probe ran %d times, want 2", calls)
	}
	if !resp.CachedAt.Equal(now) {
		t.Errorf("cached_at = %v, want the re-probe time %v", resp.CachedAt, now)
	}
}

func TestCacheIsKeyedOnHostOnly(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	calls := 0
	c := newTestCache(&now, &calls)

	c.Get(context.Background(), Options{Host: "miner.example.com", P2PPort: 30333})

	// Different ports and check selection must not trigger a second probe;
	// the caller learns what actually ran from params_used.
	resp := c.Get(context.Background(), Options{
		Host:    "miner.example.com",
		P2PPort: 40000,
		Checks:  []string{"tls"},
	})
	if !resp.Cached {
		t.Error("differing params: got cached=false, want true")
	}
	if calls != 1 {
		t.Errorf("differing params: probe ran %d times, want 1", calls)
	}
	if resp.ParamsUsed.P2PPort != 30333 {
		t.Errorf("params_used.p2p_port = %d, want the originally probed 30333",
			resp.ParamsUsed.P2PPort)
	}
}

func TestCacheHostKeyIsNormalized(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	calls := 0
	c := newTestCache(&now, &calls)

	for _, host := range []string{
		"miner.example.com",
		"MINER.example.com",
		"Miner.Example.Com.",
		"  miner.example.com  ",
	} {
		c.Get(context.Background(), Options{Host: host})
	}
	if calls != 1 {
		t.Errorf("probe ran %d times across host spellings, want 1", calls)
	}
}

func TestCacheDistinctHostsProbeIndependently(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	calls := 0
	c := newTestCache(&now, &calls)

	c.Get(context.Background(), Options{Host: "a.example.com"})
	c.Get(context.Background(), Options{Host: "b.example.com"})
	if calls != 2 {
		t.Errorf("probe ran %d times for two hosts, want 2", calls)
	}
}

// Concurrent first-requests for one host must collapse into a single probe
// rather than each racing past the miss check.
func TestCacheCollapsesConcurrentProbes(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	calls := 0
	c := &Cache{
		entries: make(map[string]*cacheEntry),
		stop:    make(chan struct{}),
		now:     func() time.Time { return now },
		run: func(_ context.Context, _ Options) map[string]Result {
			mu.Lock()
			calls++
			mu.Unlock()
			time.Sleep(10 * time.Millisecond) // widen the race window
			return map[string]Result{"p2p": {Name: "p2p", OK: true}}
		},
	}

	var wg sync.WaitGroup
	cachedCount := 0
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := c.Get(context.Background(), Options{Host: "miner.example.com"})
			mu.Lock()
			if resp.Cached {
				cachedCount++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	if calls != 1 {
		t.Errorf("probe ran %d times under concurrency, want 1", calls)
	}
	if cachedCount != 9 {
		t.Errorf("%d of 10 responses reported cached, want 9", cachedCount)
	}
}

// Failed probes are cached for the full TTL. Serving a fresh probe after a
// failure would let a caller bypass the daily limit by making probes fail.
func TestCacheStoresFailedProbes(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	calls := 0
	c := &Cache{
		entries: make(map[string]*cacheEntry),
		stop:    make(chan struct{}),
		now:     func() time.Time { return now },
		run: func(_ context.Context, _ Options) map[string]Result {
			calls++
			return map[string]Result{
				"p2p": {Name: "p2p", OK: false, Detail: "i/o timeout"},
				"tls": {Name: "tls", OK: false, Detail: "i/o timeout"},
			}
		},
	}
	opt := Options{Host: "down.example.com"}

	c.Get(context.Background(), opt)

	now = now.Add(time.Minute)
	resp := c.Get(context.Background(), opt)
	if !resp.Cached {
		t.Error("after an all-failure probe: got cached=false, want true")
	}
	if calls != 1 {
		t.Errorf("probe ran %d times, want 1 — failures must not be re-probed", calls)
	}
}

// An empty result set means no check ran, so storing it would pin the host to
// a zero-check answer for a day.
func TestCacheDoesNotStoreEmptyResults(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	calls := 0
	c := &Cache{
		entries: make(map[string]*cacheEntry),
		stop:    make(chan struct{}),
		now:     func() time.Time { return now },
		run: func(_ context.Context, opt Options) map[string]Result {
			calls++
			// Mirrors Run: unrecognized check names select nothing.
			if len(opt.Checks) > 0 && opt.Checks[0] == "bogus" {
				return map[string]Result{}
			}
			return map[string]Result{"p2p": {Name: "p2p", OK: true}}
		},
	}

	resp := c.Get(context.Background(), Options{
		Host:   "miner.example.com",
		Checks: []string{"bogus"},
	})
	if len(resp.Checks) != 0 {
		t.Fatalf("setup: got %d checks, want 0", len(resp.Checks))
	}

	// The bogus request must not have poisoned the host.
	next := c.Get(context.Background(), Options{Host: "miner.example.com"})
	if next.Cached {
		t.Error("after an empty result set: got cached=true, want false")
	}
	if len(next.Checks) == 0 {
		t.Error("follow-up request returned no checks; the empty set was cached")
	}
	if calls != 2 {
		t.Errorf("probe ran %d times, want 2", calls)
	}
}

func TestEvictExpiredRemovesStaleEntriesOnly(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	calls := 0
	c := newTestCache(&now, &calls)

	c.Get(context.Background(), Options{Host: "old.example.com"})
	now = now.Add(CacheTTL)
	c.Get(context.Background(), Options{Host: "new.example.com"})

	c.evictExpired()

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries["old.example.com"]; ok {
		t.Error("expired entry survived eviction")
	}
	if _, ok := c.entries["new.example.com"]; !ok {
		t.Error("fresh entry was evicted")
	}
}
