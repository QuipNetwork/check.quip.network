// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package ratelimit

import (
	"encoding/json"
	"math"
	"net/http"
	"sync"
	"time"

	"check.quip.network/internal"
)

const (
	// burstCapacity is how many requests a client may fire at once. The
	// bucket starts full, so a fresh client gets the whole burst.
	burstCapacity = 10
	// refillPerSecond is the sustained rate a client may hold indefinitely.
	// The node app checks two ports per second, so that pattern must never
	// drain the bucket.
	refillPerSecond = 2

	cleanupPeriod = 10 * time.Minute
	idleExpiry    = 2 * time.Hour
)

type clientState struct {
	mu sync.Mutex
	// tokens is the client's remaining request credit, refilled by elapsed
	// time rather than on a schedule, so an idle client costs nothing.
	tokens     float64
	lastRefill time.Time

	violations    int
	lastViolation time.Time
	bannedUntil   time.Time
	lastSeen      time.Time
}

// Limiter implements per-IP token bucket rate limiting with escalating bans.
type Limiter struct {
	clients sync.Map // map[string]*clientState
	stop    chan struct{}
	now     func() time.Time // overridable in tests
}

// New creates a Limiter and starts its background cleanup goroutine.
func New() *Limiter {
	return newWithClock(time.Now)
}

// newWithClock returns a Limiter reading time from now. It exists so tests can
// drive refill and ban expiry without sleeping; production callers want New.
func newWithClock(now func() time.Time) *Limiter {
	l := &Limiter{stop: make(chan struct{}), now: now}
	go l.cleanup()
	return l
}

// Stop halts the background cleanup goroutine.
func (l *Limiter) Stop() {
	close(l.stop)
}

// Middleware returns HTTP middleware that enforces rate limits.
// It skips the /health endpoint.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		ip := internal.ExtractClientIP(r)
		cs := l.getOrCreate(ip)

		cs.mu.Lock()
		now := l.now()
		cs.lastSeen = now

		// Check active ban.
		if now.Before(cs.bannedUntil) {
			retryAfter := int(math.Ceil(
				cs.bannedUntil.Sub(now).Seconds(),
			))
			violations := cs.violations
			cs.mu.Unlock()
			writeRateLimited(w, retryAfter, violations)
			return
		}

		cs.refill(now)

		if cs.tokens < 1 {
			dur := cs.recordViolation(now)
			retryAfter := int(math.Ceil(dur.Seconds()))
			violations := cs.violations
			cs.mu.Unlock()
			writeRateLimited(w, retryAfter, violations)
			return
		}

		cs.tokens--
		cs.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

// refill credits the bucket for time elapsed since the last request, capped at
// burstCapacity so idle time cannot bank unlimited credit.
func (cs *clientState) refill(now time.Time) {
	if cs.lastRefill.IsZero() {
		cs.tokens = burstCapacity
		cs.lastRefill = now
		return
	}
	elapsed := now.Sub(cs.lastRefill).Seconds()
	if elapsed <= 0 {
		return
	}
	cs.tokens = math.Min(burstCapacity, cs.tokens+elapsed*refillPerSecond)
	cs.lastRefill = now
}

// recordViolation escalates the client's violation count and sets the ban,
// returning how long the ban lasts.
func (cs *clientState) recordViolation(now time.Time) time.Duration {
	if !cs.lastViolation.IsZero() && now.Sub(cs.lastViolation) >= violationDecay {
		cs.violations = 0
	}
	cs.violations++
	cs.lastViolation = now

	dur := banDuration(cs.violations)
	cs.bannedUntil = now.Add(dur)
	return dur
}

func (l *Limiter) getOrCreate(ip string) *clientState {
	if v, ok := l.clients.Load(ip); ok {
		return v.(*clientState)
	}
	cs := &clientState{lastSeen: l.now()}
	actual, _ := l.clients.LoadOrStore(ip, cs)
	return actual.(*clientState)
}

func writeRateLimited(w http.ResponseWriter, retryAfter, banLevel int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":               "rate limited",
		"retry_after_seconds": retryAfter,
		"ban_level":           banLevel,
	})
}

func (l *Limiter) cleanup() {
	ticker := time.NewTicker(cleanupPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-ticker.C:
			now := l.now()
			l.clients.Range(func(key, value any) bool {
				cs := value.(*clientState)
				cs.mu.Lock()
				idle := now.Sub(cs.lastSeen) > idleExpiry
				banned := now.Before(cs.bannedUntil)
				cs.mu.Unlock()
				if idle && !banned {
					l.clients.Delete(key)
				}
				return true
			})
		}
	}
}
