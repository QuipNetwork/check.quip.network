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
	windowSize     = time.Minute
	maxRequests    = 5
	cleanupPeriod  = 10 * time.Minute
	idleExpiry     = 2 * time.Hour
)

// Ban durations by violation level (0-indexed).
var banDurations = []time.Duration{
	1 * time.Hour,
	24 * time.Hour,
	7 * 24 * time.Hour,
}

type clientState struct {
	mu          sync.Mutex
	timestamps  []time.Time
	violations  int
	bannedUntil time.Time
	lastSeen    time.Time
}

// Limiter implements per-IP sliding window rate limiting with
// escalating bans.
type Limiter struct {
	clients sync.Map // map[string]*clientState
	stop    chan struct{}
}

// New creates a Limiter and starts its background cleanup goroutine.
func New() *Limiter {
	l := &Limiter{stop: make(chan struct{})}
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
		now := time.Now()
		cs.lastSeen = now

		// Check active ban.
		if now.Before(cs.bannedUntil) {
			retryAfter := int(math.Ceil(
				time.Until(cs.bannedUntil).Seconds(),
			))
			cs.mu.Unlock()
			writeRateLimited(w, retryAfter, cs.violations)
			return
		}

		// Prune timestamps outside the sliding window.
		cutoff := now.Add(-windowSize)
		fresh := cs.timestamps[:0]
		for _, t := range cs.timestamps {
			if t.After(cutoff) {
				fresh = append(fresh, t)
			}
		}
		cs.timestamps = fresh

		if len(cs.timestamps) >= maxRequests {
			cs.violations++
			dur := banDuration(cs.violations)
			cs.bannedUntil = now.Add(dur)
			retryAfter := int(math.Ceil(dur.Seconds()))
			cs.mu.Unlock()
			writeRateLimited(w, retryAfter, cs.violations)
			return
		}

		cs.timestamps = append(cs.timestamps, now)
		cs.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

func (l *Limiter) getOrCreate(ip string) *clientState {
	if v, ok := l.clients.Load(ip); ok {
		return v.(*clientState)
	}
	cs := &clientState{lastSeen: time.Now()}
	actual, _ := l.clients.LoadOrStore(ip, cs)
	return actual.(*clientState)
}

func banDuration(violations int) time.Duration {
	idx := violations - 1
	if idx >= len(banDurations) {
		idx = len(banDurations) - 1
	}
	if idx < 0 {
		idx = 0
	}
	return banDurations[idx]
}

func writeRateLimited(w http.ResponseWriter, retryAfter, banLevel int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	json.NewEncoder(w).Encode(map[string]any{
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
			now := time.Now()
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
