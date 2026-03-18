// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package internal

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// privateRanges contains all RFC 1918 / RFC 6598 / loopback / link-local CIDRs.
var privateRanges []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"100.64.0.0/10",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidr := range cidrs {
		_, ipNet, _ := net.ParseCIDR(cidr)
		privateRanges = append(privateRanges, ipNet)
	}
}

// ExtractClientIP returns the client IP from request headers or RemoteAddr.
// Priority: X-Forwarded-For (first entry) → X-Real-IP → RemoteAddr.
func ExtractClientIP(r *http.Request) string {
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

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// IsPrivateIP reports whether the given IP address is in a private,
// loopback, or link-local range.
func IsPrivateIP(ip net.IP) bool {
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// ResolveAndValidate resolves a host to IPs and rejects private/loopback addresses.
// Returns the first resolved IP on success.
func ResolveAndValidate(host string) (net.IP, error) {
	// Check if host is already an IP.
	if ip := net.ParseIP(host); ip != nil {
		if IsPrivateIP(ip) {
			return nil, fmt.Errorf("private or loopback IP not allowed")
		}
		return ip, nil
	}

	addrs, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed: %w", err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses found for host")
	}

	for _, ip := range addrs {
		if IsPrivateIP(ip) {
			return nil, fmt.Errorf("host resolves to private IP")
		}
	}
	return addrs[0], nil
}
