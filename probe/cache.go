// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package probe

import (
	"context"
	"strings"
	"sync"
	"time"
)

// CacheTTL is how long a probe result stands before the host may be probed
// again. One real probe per host per day.
const CacheTTL = 24 * time.Hour

const cacheCleanupPeriod = time.Hour

// Params records the options a cached probe actually ran with. Because the
// cache is keyed on host alone, a caller may receive a result produced under
// different ports or check selection than it asked for; this field makes that
// visible rather than silent.
type Params struct {
	APIPort  int      `json:"api_port"`
	P2PPort  int      `json:"p2p_port"`
	TLSPort  int      `json:"tls_port"`
	UseHTTPS bool     `json:"https"`
	Timeout  float64  `json:"timeout_seconds"`
	Checks   []string `json:"checks"`
}

func paramsOf(opt Options) Params {
	checks := opt.Checks
	if len(checks) == 0 {
		checks = allCheckNames
	}
	return Params{
		APIPort:  opt.APIPort,
		P2PPort:  opt.P2PPort,
		TLSPort:  opt.TLSPort,
		UseHTTPS: opt.UseHTTPS,
		Timeout:  opt.Timeout.Seconds(),
		Checks:   checks,
	}
}

// Response is the /probe envelope. Check results live under Checks so that
// cache metadata can sit alongside them without colliding with check names.
type Response struct {
	Cached     bool              `json:"cached"`
	CachedAt   time.Time         `json:"cached_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
	Host       string            `json:"host"`
	ParamsUsed Params            `json:"params_used"`
	Checks     map[string]Result `json:"checks"`
}

type cacheEntry struct {
	// mu serializes probes of one host so that concurrent first-requests
	// collapse into a single outbound probe instead of a thundering herd.
	mu       sync.Mutex
	cachedAt time.Time
	params   Params
	results  map[string]Result
}

// Cache stores one probe result per host for CacheTTL.
type Cache struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry
	stop    chan struct{}
	now     func() time.Time                                 // overridable in tests
	run     func(context.Context, Options) map[string]Result // overridable in tests
}

// NewCache creates a Cache and starts its background eviction goroutine.
func NewCache() *Cache {
	c := &Cache{
		entries: make(map[string]*cacheEntry),
		stop:    make(chan struct{}),
		now:     time.Now,
		run:     Run,
	}
	go c.cleanup()
	return c
}

// Stop halts the background eviction goroutine.
func (c *Cache) Stop() {
	close(c.stop)
}

// NormalizeHost canonicalizes a host into a cache key. Hostnames are
// case-insensitive and a trailing root dot is not a distinct host.
func NormalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	return strings.TrimSuffix(h, ".")
}

// Get returns the cached result for host, running the probe only if no fresh
// entry exists. A returned Response with Cached true was served from a prior
// probe; the results were not re-fetched.
func (c *Cache) Get(ctx context.Context, opt Options) Response {
	key := NormalizeHost(opt.Host)
	e := c.entryFor(key)

	e.mu.Lock()
	defer e.mu.Unlock()

	now := c.now()
	if e.results != nil && now.Sub(e.cachedAt) < CacheTTL {
		return Response{
			Cached:     true,
			CachedAt:   e.cachedAt,
			ExpiresAt:  e.cachedAt.Add(CacheTTL),
			Host:       opt.Host,
			ParamsUsed: e.params,
			Checks:     e.results,
		}
	}

	results := c.run(ctx, opt)
	params := paramsOf(opt)

	if shouldCache(results) {
		e.cachedAt = now
		e.params = params
		e.results = results
	}

	return Response{
		Cached:     false,
		CachedAt:   now,
		ExpiresAt:  now.Add(CacheTTL),
		Host:       opt.Host,
		ParamsUsed: params,
		Checks:     results,
	}
}

// shouldCache reports whether a completed probe is worth storing.
//
// Failures are cached for the full TTL, the same as successes. An operator who
// fixes a node keeps the failed result until the entry expires, which is the
// intended cost: a shorter TTL for failures would let a caller re-probe any
// host on demand by making the probe fail, which defeats the daily limit.
// Operators who need a narrower answer can request individual checks.
//
// The one case not stored is an empty result set. Run returns no results when
// the requested check names match nothing, so storing it would pin a host to a
// zero-check answer for a day.
func shouldCache(results map[string]Result) bool {
	return len(results) > 0
}

func (c *Cache) entryFor(key string) *cacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[key]; ok {
		return e
	}
	e := &cacheEntry{}
	c.entries[key] = e
	return e
}

func (c *Cache) cleanup() {
	ticker := time.NewTicker(cacheCleanupPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			c.evictExpired()
		}
	}
}

func (c *Cache) evictExpired() {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, e := range c.entries {
		// Skip entries currently mid-probe rather than blocking on them.
		if !e.mu.TryLock() {
			continue
		}
		expired := e.results == nil || now.Sub(e.cachedAt) >= CacheTTL
		e.mu.Unlock()
		if expired {
			delete(c.entries, key)
		}
	}
}
