// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"check.quip.network/probe"
)

// newProbeHandler returns the /probe handler backed by a cache whose runner never
// touches the network, plus a counter of how many probes actually ran.
func newProbeHandler(t *testing.T) (http.HandlerFunc, func() int) {
	t.Helper()
	var mu sync.Mutex
	calls := 0
	cache := probe.NewCacheWithRunner(func(_ context.Context, opt probe.Options) map[string]probe.Result {
		mu.Lock()
		calls++
		mu.Unlock()
		return map[string]probe.Result{"p2p": {Name: "p2p", OK: true, Host: opt.Host}}
	})
	t.Cleanup(cache.Stop)
	return NewProbe(cache), func() int {
		mu.Lock()
		defer mu.Unlock()
		return calls
	}
}

func TestProbeRejectsUnknownCheckName(t *testing.T) {
	for _, tc := range []struct {
		name   string
		checks string
		bad    string
	}{
		{"single unknown name", "bogus", "bogus"},
		{"unknown mixed with valid", "p2p,bogus", "bogus"},
		// "+" decodes to a space, so this exercises the trimming path.
		{"unknown after normalization", "+NOPE+", "NOPE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, calls := newProbeHandler(t)
			rec := httptest.NewRecorder()
			h(rec, httptest.NewRequest(http.MethodGet,
				"/probe?host=miner.example.com&checks="+tc.checks, nil))

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			if body := rec.Body.String(); !strings.Contains(body, tc.bad) {
				t.Errorf("body %q does not name the rejected check %q", body, tc.bad)
			}
			// Rejecting before any outbound probe is the point of the change:
			// a 400 that still scanned the host would defeat it.
			if n := calls(); n != 0 {
				t.Errorf("probe ran %d times for a rejected request, want 0", n)
			}
		})
	}
}

func TestProbeAcceptsValidCheckSelections(t *testing.T) {
	for _, tc := range []struct{ name, checks string }{
		{"subset", "p2p,tls"},
		{"all keyword", "all"},
		{"all keyword uppercase", "ALL"},
		{"empty means all", ""},
		{"normalized name", "+P2P+"},
		{"every valid name", strings.Join(probe.CheckNames(), ",")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newProbeHandler(t)
			rec := httptest.NewRecorder()
			h(rec, httptest.NewRequest(http.MethodGet,
				"/probe?host=miner.example.com&checks="+tc.checks, nil))

			if rec.Code != http.StatusOK {
				t.Errorf("status = %d (%s), want %d",
					rec.Code, strings.TrimSpace(rec.Body.String()), http.StatusOK)
			}
		})
	}
}

// TestProbeAppliesPublicTargetRestriction is a regression test for the SSRF
// hole: /probe dials an attacker-supplied host, so the handler must mark the
// context as public-target-restricted. Before the fix the restriction was never
// applied on the request path and dialContext took its unrestricted branch,
// making /probe an SSRF primitive against RFC1918 and metadata targets.
func TestProbeAppliesPublicTargetRestriction(t *testing.T) {
	var mu sync.Mutex
	restricted := false
	cache := probe.NewCacheWithRunner(func(ctx context.Context, _ probe.Options) map[string]probe.Result {
		mu.Lock()
		restricted = probe.TargetsAreRestricted(ctx)
		mu.Unlock()
		return map[string]probe.Result{"api_port": {Name: "api_port", OK: true}}
	})
	t.Cleanup(cache.Stop)

	rec := httptest.NewRecorder()
	NewProbe(cache)(rec, httptest.NewRequest(http.MethodGet,
		"/probe?host=miner.example.com&checks=api_port", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s), want %d",
			rec.Code, strings.TrimSpace(rec.Body.String()), http.StatusOK)
	}
	mu.Lock()
	defer mu.Unlock()
	if !restricted {
		t.Error("probe runner received a context without the public-target restriction; " +
			"dialContext would have dialed the host unrestricted")
	}
}

// TestValidateProbeHostRejectsNonPublicLiterals is a regression test for the
// incomplete IP blocklist: RFC1918, CGNAT, and documentation literals must be
// rejected by the handler's own validation before any DNS lookup is spent.
func TestValidateProbeHostRejectsNonPublicLiterals(t *testing.T) {
	for _, host := range []string{
		"10.0.0.1", "172.16.0.1", "192.168.1.1", // RFC1918
		"169.254.169.254",  // cloud metadata
		"127.0.0.1", "::1", // loopback
		"100.64.1.1",       // RFC 6598 CGNAT
		"192.0.2.1",        // RFC 5737 TEST-NET-1
		"198.18.0.1",       // RFC 2544 benchmarking
		"::ffff:127.0.0.1", // IPv4-mapped loopback
	} {
		if err := validateProbeHost(host); err == nil {
			t.Errorf("validateProbeHost(%q) = nil, want rejection", host)
		}
	}

	for _, host := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if err := validateProbeHost(host); err != nil {
			t.Errorf("validateProbeHost(%q) = %v, want nil", host, err)
		}
	}
}
