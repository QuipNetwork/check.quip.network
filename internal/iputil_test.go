// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package internal

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Regression: X-Forwarded-For must never take precedence over the transport
// peer. This value keys the rate limiter, so trusting a client-supplied header
// let any caller mint unlimited identities and bypass both the token bucket and
// the escalating ban.
func TestExtractClientIPIgnoresSpoofedForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Real-IP", "5.6.7.8")

	if got := ExtractClientIP(req); got != "203.0.113.9" {
		t.Errorf("ExtractClientIP = %q, want the transport peer 203.0.113.9", got)
	}
}

// A direct client sending a different XFF per request must map to one stable
// bucket key, which is what actually stops the rate-limit bypass.
func TestExtractClientIPIsStableAcrossSpoofedRequests(t *testing.T) {
	seen := map[string]bool{}
	for _, spoofed := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"} {
		req := httptest.NewRequest(http.MethodGet, "/ip", nil)
		req.RemoteAddr = "198.51.100.7:40000"
		req.Header.Set("X-Forwarded-For", spoofed)
		seen[ExtractClientIP(req)] = true
	}
	if len(seen) != 1 {
		t.Errorf("spoofed X-Forwarded-For produced %d identities (%v), want 1", len(seen), seen)
	}
}

// Behind a trusted reverse proxy the peer is loopback/private, so the forwarded
// headers must be honoured, and the RIGHTMOST entry is the one the proxy
// appended, not the client-supplied leftmost value.
func TestExtractClientIPBehindProxyUsesAppendedEntry(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	req.RemoteAddr = "127.0.0.1:8080"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.9")

	if got := ExtractClientIP(req); got != "203.0.113.9" {
		t.Errorf("ExtractClientIP = %q, want the proxy-appended 203.0.113.9", got)
	}
}

func TestExtractClientIPFallsBackToRealIPBehindProxy(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	req.RemoteAddr = "10.0.0.5:3000"
	req.Header.Set("X-Real-IP", "203.0.113.9")

	if got := ExtractClientIP(req); got != "203.0.113.9" {
		t.Errorf("ExtractClientIP = %q, want 203.0.113.9", got)
	}
}

func TestExtractClientIPWithoutHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	req.RemoteAddr = "203.0.113.9:1234"

	if got := ExtractClientIP(req); got != "203.0.113.9" {
		t.Errorf("ExtractClientIP = %q, want 203.0.113.9", got)
	}
}
