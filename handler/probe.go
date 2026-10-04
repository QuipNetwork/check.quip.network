// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"check.quip.network/probe"
)

// NewProbe returns the GET /probe handler backed by cache.
//
// Unlike /checkport (self-IP only), this targets an explicit host so node-quest
// and operators can verify public infrastructure. Subject to the global per-IP
// rate limit (5/min by default) and, per target host, to one real probe per
// day; repeat callers receive the cached result.
func NewProbe(cache *probe.Cache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		checkProbe(w, r, cache)
	}
}

// checkProbe handles GET /probe?host=HOST&api_port=&p2p_port=&tls_port=&checks=&http=
func checkProbe(w http.ResponseWriter, r *http.Request, cache *probe.Cache) {
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	if host == "" {
		writeError(w, http.StatusBadRequest, "host parameter required")
		return
	}
	if err := validateProbeHost(host); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	apiPort, err := parsePortDefault(r.URL.Query().Get("api_port"), probe.DefaultAPIPort)
	if err != nil {
		writeError(w, http.StatusBadRequest, "api_port must be 1-65535")
		return
	}
	p2pPort, err := parsePortDefault(r.URL.Query().Get("p2p_port"), probe.DefaultP2PPort)
	if err != nil {
		writeError(w, http.StatusBadRequest, "p2p_port must be 1-65535")
		return
	}
	// tls_port: empty -> 443; "0" -> skip TLS
	tlsRaw := strings.TrimSpace(r.URL.Query().Get("tls_port"))
	tlsPort := probe.DefaultTLSPort
	if tlsRaw == "0" {
		tlsPort = 0
	} else if tlsRaw != "" {
		tlsPort, err = parsePortDefault(tlsRaw, probe.DefaultTLSPort)
		if err != nil {
			writeError(w, http.StatusBadRequest, "tls_port must be 0-65535")
			return
		}
	}

	useHTTPS := true
	if v := strings.TrimSpace(r.URL.Query().Get("http")); v == "1" || strings.EqualFold(v, "true") {
		useHTTPS = false
	}

	// Reject unknown check names rather than probing and returning an empty
	// result set: an empty set is indistinguishable from "every check failed",
	// and caching it would pin the host to that answer for the full TTL.
	var checks []string
	if raw := strings.TrimSpace(r.URL.Query().Get("checks")); raw != "" && !strings.EqualFold(raw, "all") {
		for c := range strings.SplitSeq(raw, ",") {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			if !probe.ValidCheckName(c) {
				writeError(w, http.StatusBadRequest, fmt.Sprintf(
					"unknown check %q: valid checks are %s",
					c, strings.Join(probe.CheckNames(), ", ")))
				return
			}
			checks = append(checks, strings.ToLower(c))
		}
	}

	timeout := probe.DefaultConnectTimeout
	if raw := strings.TrimSpace(r.URL.Query().Get("timeout")); raw != "" {
		if sec, err := strconv.ParseFloat(raw, 64); err == nil && sec > 0 && sec <= 30 {
			timeout = time.Duration(sec * float64(time.Second))
		}
	}

	// The probe dials an attacker-supplied host, so the context MUST carry the
	// public-target restriction. Without it `dialContext` takes the unrestricted
	// branch and the host string is dialed as-is, which turns /probe into an SSRF
	// primitive against anything the service can reach (RFC1918 ranges, the
	// 169.254.169.254 metadata endpoint, and internal-only DNS names that
	// validateProbeHost cannot reject because it only inspects the literal
	// string). `dialContext` re-resolves the name and refuses any address that
	// is not globally routable, which also closes the DNS-rebinding window.
	ctx, cancel := context.WithTimeout(r.Context(), timeout+2*time.Second)
	defer cancel()
	ctx = probe.WithPublicTargets(ctx)

	// Cache is keyed on host alone, so a fresh entry is returned even when the
	// port or check parameters differ; params_used reports what actually ran.
	resp := cache.Get(ctx, probe.Options{
		Host:     host,
		APIPort:  apiPort,
		P2PPort:  p2pPort,
		TLSPort:  tlsPort,
		UseHTTPS: useHTTPS,
		Timeout:  timeout,
		Checks:   checks,
	})

	w.Header().Set("Content-Type", "application/json")
	if resp.Cached {
		w.Header().Set("X-Cache", "HIT")
	} else {
		w.Header().Set("X-Cache", "MISS")
	}
	w.Header().Set("X-Cache-Cached-At", resp.CachedAt.UTC().Format(time.RFC3339))
	w.Header().Set("X-Cache-Expires", resp.ExpiresAt.UTC().Format(time.RFC3339))
	_ = json.NewEncoder(w).Encode(resp)
}

func parsePortDefault(raw string, def int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return 0, errInvalidPort
	}
	return n, nil
}

var errInvalidPort = &probeHostError{msg: "invalid port"}

type probeHostError struct{ msg string }

func (e *probeHostError) Error() string { return e.msg }

func validateProbeHost(host string) error {
	if len(host) > 253 {
		return &probeHostError{msg: "host too long"}
	}
	// Reject empty and characters that are never valid in hostnames/IPs.
	if strings.ContainsAny(host, " \t\r\n/") {
		return &probeHostError{msg: "host must be a hostname or IP, not a URL"}
	}
	if strings.EqualFold(host, "localhost") {
		return &probeHostError{msg: "host address not allowed"}
	}
	// Block the full set of non-public destinations, not just loopback and
	// link-local. A literal RFC1918 address previously passed this check and was
	// dialed directly, exposing hosts on the service's own private network. The
	// dialer re-validates resolved addresses too (see probe.publicAddress), but
	// rejecting obvious literals here fails fast and costs no DNS lookup.
	if ip := net.ParseIP(host); ip != nil {
		if !publicLiteral(ip) {
			return &probeHostError{msg: "host address not allowed"}
		}
	}
	return nil
}

// publicLiteral reports whether a literal IP is safe to probe. Cloud metadata
// (169.254.169.254) falls under the link-local check and the IPv6 unique-local
// range under the private check.
func publicLiteral(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	// IsPrivate covers RFC1918 (10/8, 172.16/12, 192.168/16) and IPv6 fc00::/7.
	if ip.IsPrivate() {
		return false
	}
	// Carrier-grade NAT, IETF protocol assignments, benchmarking, and
	// documentation space all parse as global unicast but are unroutable.
	for _, cidr := range nonPublicCIDRs {
		if cidr.Contains(ip) {
			return false
		}
	}
	return true
}

// nonPublicCIDRs are ranges that parse as global unicast but must never be
// probed: shared address space, protocol assignments, benchmarking, and docs.
var nonPublicCIDRs = func() []*net.IPNet {
	raw := []string{
		"100.64.0.0/10",   // RFC 6598 carrier-grade NAT
		"192.0.0.0/24",    // RFC 6890 IETF protocol assignments
		"192.0.2.0/24",    // RFC 5737 TEST-NET-1
		"198.18.0.0/15",   // RFC 2544 benchmarking
		"198.51.100.0/24", // RFC 5737 TEST-NET-2
		"203.0.113.0/24",  // RFC 5737 TEST-NET-3
		"240.0.0.0/4",     // reserved
		"2001:db8::/32",   // RFC 3849 documentation
	}
	out := make([]*net.IPNet, 0, len(raw))
	for _, c := range raw {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}()
