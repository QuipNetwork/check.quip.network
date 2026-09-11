// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

// Package checkcache stores the results of self-targeted connectivity checks so
// that /checkport and /checkconn dial a caller's own address at most once per
// TTL. Unlike the probe cache, these checks can only target the caller, so the
// cache exists to shed load rather than to close an abuse vector - which is why
// failures expire quickly instead of standing for the full window.
package checkcache

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const (
	// SuccessTTL is how long a reachable result stands. A port that answered
	// is unlikely to stop answering in a way the caller needs told about
	// within the hour.
	SuccessTTL = time.Hour
	// FailureTTL is deliberately short. The usual caller of a failing check
	// is an operator fixing a firewall and retrying, and making them wait an
	// hour to see the fix would be worse than the load it saves. One minute
	// still collapses a retry storm.
	FailureTTL = time.Minute

	cleanupPeriod = 10 * time.Minute
)

// Key identifies one cached check. Kind separates the TCP and QUIC checks so
// they can share a cache without colliding on the same address.
type Key struct {
	Kind string
	IP   string
	Port int
}

func (k Key) String() string {
	return fmt.Sprintf("%s|%s|%d", k.Kind, k.IP, k.Port)
}

// Result is one completed check. OK selects the TTL; Body is the handler's JSON
// payload, stored as-is so the cache stays ignorant of check semantics.
type Result struct {
	OK   bool
	Body map[string]any
}

// Response wraps a Result with the cache metadata handlers surface to callers.
type Response struct {
	Result
	Cached    bool
	CachedAt  time.Time
	ExpiresAt time.Time
}

// ttl returns how long a result of this outcome stands.
func (r Result) ttl() time.Duration {
	if r.OK {
		return SuccessTTL
	}
	return FailureTTL
}

type entry struct {
	// mu serializes checks of one key so that concurrent first-requests
	// collapse into a single outbound dial instead of a thundering herd.
	mu       sync.Mutex
	cachedAt time.Time
	result   Result
	stored   bool
}

// Cache stores one result per Key for the TTL its outcome selects.
type Cache struct {
	mu      sync.Mutex
	entries map[string]*entry
	stop    chan struct{}
	now     func() time.Time // overridable in tests
}

// New creates a Cache and starts its background eviction goroutine.
func New() *Cache {
	return newWithClock(time.Now)
}

// newWithClock returns a Cache reading time from now. It exists so tests can
// drive TTL expiry without sleeping; production callers want New.
func newWithClock(now func() time.Time) *Cache {
	c := &Cache{
		entries: make(map[string]*entry),
		stop:    make(chan struct{}),
		now:     now,
	}
	go c.cleanup()
	return c
}

// Stop halts the background eviction goroutine.
func (c *Cache) Stop() {
	close(c.stop)
}

// Get returns the cached result for key, calling run only when no fresh entry
// exists. A Response with Cached true was produced by an earlier check; no
// connection was made on this request.
func (c *Cache) Get(ctx context.Context, key Key, run func(context.Context) Result) Response {
	e := c.entryFor(key.String())

	e.mu.Lock()
	defer e.mu.Unlock()

	now := c.now()
	if e.stored && now.Sub(e.cachedAt) < e.result.ttl() {
		return Response{
			Result:    e.result,
			Cached:    true,
			CachedAt:  e.cachedAt,
			ExpiresAt: e.cachedAt.Add(e.result.ttl()),
		}
	}

	result := run(ctx)
	e.cachedAt = now
	e.result = result
	e.stored = true

	return Response{
		Result:    result,
		Cached:    false,
		CachedAt:  now,
		ExpiresAt: now.Add(result.ttl()),
	}
}

func (c *Cache) entryFor(key string) *entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[key]; ok {
		return e
	}
	e := &entry{}
	c.entries[key] = e
	return e
}

func (c *Cache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *Cache) cleanup() {
	ticker := time.NewTicker(cleanupPeriod)
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
		// Skip entries currently mid-check rather than blocking on them.
		if !e.mu.TryLock() {
			continue
		}
		expired := !e.stored || now.Sub(e.cachedAt) >= e.result.ttl()
		e.mu.Unlock()
		if expired {
			delete(c.entries, key)
		}
	}
}
