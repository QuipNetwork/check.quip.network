// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package checkcache

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func testCache(t *testing.T) (*Cache, *fakeClock) {
	t.Helper()
	clock := newFakeClock()
	c := newWithClock(clock.Now)
	t.Cleanup(c.Stop)
	return c, clock
}

// counting returns a runner that reports ok and tallies how often it ran.
func counting(ok bool, calls *atomic.Int64) func(context.Context) Result {
	return func(context.Context) Result {
		calls.Add(1)
		return Result{OK: ok, Body: map[string]any{"reachable": ok}}
	}
}

var tcpKey = Key{Kind: "tcp", IP: "198.51.100.1", Port: 30333}

func TestFirstRequestRunsTheCheck(t *testing.T) {
	c, _ := testCache(t)
	var calls atomic.Int64

	resp := c.Get(context.Background(), tcpKey, counting(true, &calls))

	if calls.Load() != 1 {
		t.Fatalf("runner calls: got %d, want 1", calls.Load())
	}
	if resp.Cached {
		t.Error("first response must report cached false")
	}
	if resp.Body["reachable"] != true {
		t.Errorf("body not passed through: %v", resp.Body)
	}
}

func TestRepeatRequestIsServedFromCache(t *testing.T) {
	c, _ := testCache(t)
	var calls atomic.Int64

	c.Get(context.Background(), tcpKey, counting(true, &calls))
	resp := c.Get(context.Background(), tcpKey, counting(true, &calls))

	if calls.Load() != 1 {
		t.Fatalf("runner calls: got %d, want 1 - the second request re-ran the check",
			calls.Load())
	}
	if !resp.Cached {
		t.Error("second response must report cached true")
	}
}

func TestSuccessIsCachedForAnHour(t *testing.T) {
	c, clock := testCache(t)
	var calls atomic.Int64

	c.Get(context.Background(), tcpKey, counting(true, &calls))

	clock.Advance(SuccessTTL - time.Second)
	if resp := c.Get(context.Background(), tcpKey, counting(true, &calls)); !resp.Cached {
		t.Fatal("a success one second short of its TTL must still be cached")
	}

	clock.Advance(2 * time.Second)
	if resp := c.Get(context.Background(), tcpKey, counting(true, &calls)); resp.Cached {
		t.Fatal("a success past its TTL must be re-checked")
	}
	if calls.Load() != 2 {
		t.Fatalf("runner calls: got %d, want 2", calls.Load())
	}
}

func TestFailureIsCachedOnlyBriefly(t *testing.T) {
	c, clock := testCache(t)
	var calls atomic.Int64

	c.Get(context.Background(), tcpKey, counting(false, &calls))

	clock.Advance(FailureTTL - time.Second)
	if resp := c.Get(context.Background(), tcpKey, counting(false, &calls)); !resp.Cached {
		t.Fatal("a failure inside its short TTL must be cached to absorb retry storms")
	}

	clock.Advance(2 * time.Second)
	resp := c.Get(context.Background(), tcpKey, counting(false, &calls))
	if resp.Cached {
		t.Fatal("a failure past its short TTL must be re-checked so operators see a fix")
	}
	if calls.Load() != 2 {
		t.Fatalf("runner calls: got %d, want 2", calls.Load())
	}
}

func TestFailureThenSuccessSwitchesToTheLongTTL(t *testing.T) {
	c, clock := testCache(t)
	var calls atomic.Int64

	c.Get(context.Background(), tcpKey, counting(false, &calls))
	clock.Advance(FailureTTL + time.Second)
	// The operator opened the port.
	c.Get(context.Background(), tcpKey, counting(true, &calls))

	clock.Advance(FailureTTL + time.Second)
	if resp := c.Get(context.Background(), tcpKey, counting(true, &calls)); !resp.Cached {
		t.Fatal("a success must be held for SuccessTTL, not the failure TTL")
	}
}

func TestExpiresAtReflectsTheOutcomeTTL(t *testing.T) {
	c, clock := testCache(t)
	var calls atomic.Int64

	start := clock.Now()
	ok := c.Get(context.Background(), tcpKey, counting(true, &calls))
	if want := start.Add(SuccessTTL); !ok.ExpiresAt.Equal(want) {
		t.Errorf("success ExpiresAt: got %v, want %v", ok.ExpiresAt, want)
	}

	failKey := Key{Kind: "tcp", IP: "198.51.100.2", Port: 30333}
	bad := c.Get(context.Background(), failKey, counting(false, &calls))
	if want := start.Add(FailureTTL); !bad.ExpiresAt.Equal(want) {
		t.Errorf("failure ExpiresAt: got %v, want %v", bad.ExpiresAt, want)
	}
}

func TestKeyDimensionsDoNotCollide(t *testing.T) {
	tests := []struct {
		name string
		key  Key
	}{
		{"different port", Key{Kind: "tcp", IP: "198.51.100.1", Port: 20049}},
		{"different ip", Key{Kind: "tcp", IP: "203.0.113.9", Port: 30333}},
		{"different kind", Key{Kind: "quic", IP: "198.51.100.1", Port: 30333}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := testCache(t)
			var calls atomic.Int64

			c.Get(context.Background(), tcpKey, counting(true, &calls))
			resp := c.Get(context.Background(), tc.key, counting(true, &calls))

			if resp.Cached {
				t.Fatalf("%v was served from the entry for %v", tc.key, tcpKey)
			}
			if calls.Load() != 2 {
				t.Fatalf("runner calls: got %d, want 2", calls.Load())
			}
		})
	}
}

func TestConcurrentFirstRequestsRunOneCheck(t *testing.T) {
	c, _ := testCache(t)
	var calls atomic.Int64

	release := make(chan struct{})
	slow := func(context.Context) Result {
		calls.Add(1)
		<-release
		return Result{OK: true, Body: map[string]any{"reachable": true}}
	}

	const callers = 8
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			c.Get(context.Background(), tcpKey, slow)
		}()
	}

	// Let the winner reach the runner, then unblock everyone.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if calls.Load() != 1 {
		t.Fatalf("runner calls: got %d, want 1 - concurrent first requests must collapse",
			calls.Load())
	}
}

func TestExpiredEntriesAreEvicted(t *testing.T) {
	c, clock := testCache(t)
	var calls atomic.Int64

	c.Get(context.Background(), tcpKey, counting(true, &calls))
	if got := c.size(); got != 1 {
		t.Fatalf("entries after one check: got %d, want 1", got)
	}

	clock.Advance(SuccessTTL + time.Second)
	c.evictExpired()

	if got := c.size(); got != 0 {
		t.Fatalf("entries after eviction: got %d, want 0", got)
	}
}
