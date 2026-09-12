// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package internal

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
)

// ExtractClientIP returns the client IP for a request.
//
// X-Forwarded-For and X-Real-IP are honoured only when the request reached us
// from a trusted proxy; otherwise the connection address wins. The extracted
// value is the rate-limit bucket key, the cache key and the dial target for
// /checkport and /checkconn, so a caller that can name its own IP can pick a
// fresh bucket, choose a cache entry and aim the dialler. In production nginx
// terminates TLS in front of this service and overwrites both headers with
// $remote_addr, but the binary must not depend on that to be safe.
func ExtractClientIP(r *http.Request) string {
	remote := remoteAddrIP(r)

	if !IsTrustedProxy(remote) {
		return remote
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		ip := strings.TrimSpace(parts[0])
		if ip != "" {
			return ip
		}
	}

	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return strings.TrimSpace(realIP)
	}

	return remote
}

// remoteAddrIP is the address the connection actually came from, with the port
// stripped. It is the only value in a request a caller cannot choose.
func remoteAddrIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// trustedNets holds the operator-configured proxy networks. It is written once
// at startup, before the listener accepts anything, and only read afterwards.
var trustedNets []*net.IPNet

// SetTrustedProxies replaces the set of networks whose forwarding headers are
// believed, in addition to loopback. Entries may be CIDRs ("10.4.0.0/16") or
// bare addresses ("10.4.1.9"). Passing nil clears it. An unparseable entry is
// an error and leaves the previous set untouched, so a typo in configuration
// fails startup rather than silently trusting nothing — or everything.
func SetTrustedProxies(cidrs []string) error {
	nets := make([]*net.IPNet, 0, len(cidrs))

	for _, entry := range cidrs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if _, n, err := net.ParseCIDR(entry); err == nil {
			nets = append(nets, n)
			continue
		}

		ip := net.ParseIP(entry)
		if ip == nil {
			return fmt.Errorf("trusted proxy %q is neither an IP address nor a CIDR block", entry)
		}
		nets = append(nets, singleHostNet(ip))
	}

	trustedNets = nets
	return nil
}

// singleHostNet turns a bare address into the /32 or /128 containing only it.
func singleHostNet(ip net.IP) *net.IPNet {
	bits := 8 * net.IPv6len
	if v4 := ip.To4(); v4 != nil {
		ip, bits = v4, 8*net.IPv4len
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
}

// IsTrustedProxy reports whether forwarding headers from this address may be
// believed. Loopback covers the deployed shape, where nginx proxies to the
// service over 127.0.0.1 inside one container; anything else has to be
// configured deliberately.
func IsTrustedProxy(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}

	if ip.IsLoopback() {
		return true
	}

	for _, n := range trustedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ConfigureTrustedProxiesFromEnv applies TRUSTED_PROXIES, a comma-separated
// list of CIDRs or addresses. Unset means loopback only, which is the deployed
// shape. Call it during startup and treat the error as fatal.
func ConfigureTrustedProxiesFromEnv() error {
	raw := os.Getenv("TRUSTED_PROXIES")
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return SetTrustedProxies(strings.Split(raw, ","))
}
