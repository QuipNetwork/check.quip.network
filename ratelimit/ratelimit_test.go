// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package ratelimit

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeClock drives the limiter without sleeping. The limiter reads it from
// several goroutines in the concurrency test, so it carries its own mutex.
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

// testLimiter returns a limiter on a fake clock, stopped when the test ends.
func testLimiter(t *testing.T) (*Limiter, *fakeClock) {
	t.Helper()
	clock := newFakeClock()
	l := newWithClock(clock.Now)
	t.Cleanup(l.Stop)
	return l, clock
}

// get sends one request through the middleware and returns the status code.
func get(t *testing.T, l *Limiter, ip, path string) (int, map[string]any) {
	t.Helper()
	handler := l.Middleware(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodGet, path, nil)
	// Identity comes from the connection. A forwarding header would be ignored
	// here, because httptest's RemoteAddr is not a trusted proxy.
	req.RemoteAddr = net.JoinHostPort(ip, "51000")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var body map[string]any
	if rec.Code != http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode %d response: %v", rec.Code, err)
		}
	}
	return rec.Code, body
}

func TestBurstUpToCapacityIsAllowed(t *testing.T) {
	l, _ := testLimiter(t)

	// No time advances: every request lands in the same instant.
	for i := range burstCapacity {
		if code, _ := get(t, l, "198.51.100.1", "/ip"); code != http.StatusOK {
			t.Fatalf("request %d of a %d burst: got %d, want 200",
				i+1, burstCapacity, code)
		}
	}
}

func TestRequestBeyondBurstIsBanned(t *testing.T) {
	l, _ := testLimiter(t)

	for range burstCapacity {
		get(t, l, "198.51.100.2", "/ip")
	}

	code, body := get(t, l, "198.51.100.2", "/ip")
	if code != http.StatusTooManyRequests {
		t.Fatalf("request past an empty bucket: got %d, want 429", code)
	}
	if body["error"] != "rate limited" {
		t.Errorf("error field: got %v, want \"rate limited\"", body["error"])
	}
}

func TestSustainedTwoPerSecondIsNeverBanned(t *testing.T) {
	l, clock := testLimiter(t)

	// The node app checks two ports per second. That pattern must run
	// indefinitely without tripping the limiter.
	for i := range 200 {
		for range 2 {
			if code, _ := get(t, l, "198.51.100.3", "/checkport"); code != http.StatusOK {
				t.Fatalf("second %d of sustained 2/s traffic: got %d, want 200", i, code)
			}
		}
		clock.Advance(time.Second)
	}
}

func TestSustainedFourPerSecondIsBanned(t *testing.T) {
	l, clock := testLimiter(t)

	banned := false
	for range 30 {
		for range 4 {
			if code, _ := get(t, l, "198.51.100.4", "/checkport"); code == http.StatusTooManyRequests {
				banned = true
			}
		}
		if banned {
			break
		}
		clock.Advance(time.Second)
	}
	if !banned {
		t.Fatal("sustained 4/s traffic was never banned")
	}
}

func TestTokensRefillOverTime(t *testing.T) {
	l, clock := testLimiter(t)

	for range burstCapacity {
		get(t, l, "198.51.100.5", "/ip")
	}
	// One second of quiet restores refillPerSecond tokens.
	clock.Advance(time.Second)

	for i := range refillPerSecond {
		if code, _ := get(t, l, "198.51.100.5", "/ip"); code != http.StatusOK {
			t.Fatalf("refilled token %d: got %d, want 200", i+1, code)
		}
	}
	if code, _ := get(t, l, "198.51.100.5", "/ip"); code != http.StatusTooManyRequests {
		t.Fatalf("beyond refilled tokens: got %d, want 429", code)
	}
}

func TestBanNeverExceedsFiveMinutes(t *testing.T) {
	l, clock := testLimiter(t)

	// Trip the limiter repeatedly so violations climb past the ladder.
	for range 10 {
		for range burstCapacity + 1 {
			get(t, l, "198.51.100.6", "/ip")
		}
		_, body := get(t, l, "198.51.100.6", "/ip")
		retry, ok := body["retry_after_seconds"].(float64)
		if !ok {
			t.Fatalf("retry_after_seconds missing from %v", body)
		}
		if retry > maxBanDuration.Seconds() {
			t.Fatalf("ban of %.0fs exceeds the %.0fs ceiling",
				retry, maxBanDuration.Seconds())
		}
		// Clear the ban and refill the bucket, but stay inside the decay
		// window so violations keep climbing past the end of the ladder.
		clock.Advance(maxBanDuration + time.Second)
	}
}

func TestBanExpires(t *testing.T) {
	l, clock := testLimiter(t)

	for range burstCapacity + 1 {
		get(t, l, "198.51.100.7", "/ip")
	}
	if code, _ := get(t, l, "198.51.100.7", "/ip"); code != http.StatusTooManyRequests {
		t.Fatal("expected an active ban")
	}

	clock.Advance(maxBanDuration + time.Second)

	if code, _ := get(t, l, "198.51.100.7", "/ip"); code != http.StatusOK {
		t.Fatal("request after the ban expired: want 200")
	}
}

func TestViolationsDecayAfterQuietPeriod(t *testing.T) {
	l, clock := testLimiter(t)

	trip := func() float64 {
		t.Helper()
		for range burstCapacity + 1 {
			get(t, l, "198.51.100.8", "/ip")
		}
		_, body := get(t, l, "198.51.100.8", "/ip")
		level, _ := body["ban_level"].(float64)
		return level
	}

	first := trip()
	clock.Advance(violationDecay + time.Minute)
	second := trip()

	if second != first {
		t.Fatalf("ban level after a quiet %v: got %v, want it reset to %v",
			violationDecay, second, first)
	}
}

func TestViolationsEscalateWhileAbusive(t *testing.T) {
	l, clock := testLimiter(t)

	trip := func() float64 {
		t.Helper()
		for range burstCapacity + 1 {
			get(t, l, "198.51.100.9", "/ip")
		}
		_, body := get(t, l, "198.51.100.9", "/ip")
		level, _ := body["ban_level"].(float64)
		return level
	}

	first := trip()
	// Long enough to clear the ban, short enough that violations stand.
	clock.Advance(maxBanDuration + time.Second)
	second := trip()

	if second <= first {
		t.Fatalf("repeat violation inside the decay window: got level %v, want above %v",
			second, first)
	}
}

func TestHealthIsNotRateLimited(t *testing.T) {
	l, _ := testLimiter(t)

	for range burstCapacity * 3 {
		if code, _ := get(t, l, "198.51.100.10", "/health"); code != http.StatusOK {
			t.Fatalf("/health returned %d", code)
		}
	}
}

func TestLimitsAreTrackedPerIP(t *testing.T) {
	l, _ := testLimiter(t)

	for range burstCapacity + 1 {
		get(t, l, "198.51.100.11", "/ip")
	}
	if code, _ := get(t, l, "198.51.100.11", "/ip"); code != http.StatusTooManyRequests {
		t.Fatal("expected the noisy IP to be banned")
	}
	if code, _ := get(t, l, "198.51.100.12", "/ip"); code != http.StatusOK {
		t.Fatal("a second IP must be unaffected by the first IP's ban")
	}
}
