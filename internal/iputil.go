// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package internal

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ExtractClientIP returns the client IP used for rate limiting and self-targeted
// checks.
//
// Priority: RemoteAddr, then X-Forwarded-For (last entry), then X-Real-IP.
//
// The forwarding headers are consulted ONLY as a fallback, never in preference to
// the transport peer. They are trivially attacker-controlled, and this value keys
// the rate limiter (see ratelimit.Limiter.Middleware), so preferring them would
// let a caller mint unlimited identities simply by sending a fresh
// X-Forwarded-For per request and bypass the bucket and the escalating ban
// entirely.
//
// When a trusted proxy is in front of the service it appends the real peer to
// the right-hand end of X-Forwarded-For; the entries it added are the
// trustworthy ones, so the LAST value is used. The leftmost entry is
// client-supplied and must never be trusted.
func ExtractClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	// A transport peer that is itself a private/loopback address means the
	// request arrived through a reverse proxy, so the forwarded headers are the
	// only source of the real client identity.
	if host != "" && !isPublicIP(host) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
			return realIP
		}
	}
	if host != "" {
		return host
	}
	// RemoteAddr was unusable; fall back to the headers rather than bucket every
	// such caller under one shared empty key.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
			return ip
		}
	}
	return strings.TrimSpace(r.Header.Get("X-Real-IP"))
}

// isPublicIP reports whether host parses as a globally routable IP literal.
// Anything that does not parse is treated as non-public, which keeps the caller
// on the proxy-aware path.
func isPublicIP(host string) bool {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return addr.IsGlobalUnicast() && !addr.IsPrivate() &&
		!addr.IsLoopback() && !addr.IsLinkLocalUnicast()
}
