// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package handler

import (
	"context"
	"encoding/json"
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

	var checks []string
	if raw := strings.TrimSpace(r.URL.Query().Get("checks")); raw != "" && !strings.EqualFold(raw, "all") {
		for _, c := range strings.Split(raw, ",") {
			c = strings.TrimSpace(c)
			if c != "" {
				checks = append(checks, c)
			}
		}
	}

	timeout := probe.DefaultConnectTimeout
	if raw := strings.TrimSpace(r.URL.Query().Get("timeout")); raw != "" {
		if sec, err := strconv.ParseFloat(raw, 64); err == nil && sec > 0 && sec <= 30 {
			timeout = time.Duration(sec * float64(time.Second))
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout+2*time.Second)
	defer cancel()

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
	// Block obvious loopback/metadata abuse while still allowing public miner IPs.
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return &probeHostError{msg: "host address not allowed"}
		}
		// Cloud metadata well-known address
		if ip.String() == "169.254.169.254" {
			return &probeHostError{msg: "host address not allowed"}
		}
	}
	return nil
}
