// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

// Package probe implements host-targeted connectivity checks for node operator
// reward boosts. This is the source of truth for check semantics; node-quest
// and other clients call the HTTP API rather than reimplementing checks.
package probe

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
)

const (
	DefaultAPIPort = 20049
	DefaultP2PPort = 30333
	DefaultTLSPort = 443

	DefaultConnectTimeout = 5 * time.Second
	DefaultReadTimeout    = 5 * time.Second
	maxBodyBytes          = 4096
)

// Result is one named check outcome.
type Result struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	Host   string `json:"host,omitempty"`
	Port   *int   `json:"port,omitempty"`
}

// Options controls which checks run and against which ports.
type Options struct {
	Host     string
	APIPort  int
	P2PPort  int
	TLSPort  int  // 0 skips TLS
	UseHTTPS bool // API/telemetry/dashboard scheme
	Timeout  time.Duration
	// Checks empty means all six boosts.
	Checks []string
}

var allCheckNames = []string{
	"p2p", "api_port", "tls", "rpc", "telemetry", "dashboard",
}

// CheckNames returns the names of every check Run can execute. The result is a
// copy, so callers cannot reorder or overwrite the package list.
func CheckNames() []string {
	names := make([]string, len(allCheckNames))
	copy(names, allCheckNames)
	return names
}

// ValidCheckName reports whether name selects a check Run can execute. Names are
// matched after trimming and lowercasing, the same normalization Run applies, so
// a name accepted here always selects a check once Run sees it.
func ValidCheckName(name string) bool {
	return slices.Contains(allCheckNames, strings.TrimSpace(strings.ToLower(name)))
}

var dashboardMarkers = []string{
	"quip", "dashboard", "node manager", "__next", "vite",
}

// Run executes the selected checks and returns results keyed by name.
func Run(ctx context.Context, opt Options) map[string]Result {
	if opt.APIPort == 0 {
		opt.APIPort = DefaultAPIPort
	}
	if opt.P2PPort == 0 {
		opt.P2PPort = DefaultP2PPort
	}
	if opt.Timeout <= 0 {
		opt.Timeout = DefaultConnectTimeout
	}
	// Default TLS port only when unset: use -1 sentinel? API uses 0 to skip.
	// Caller sets TLSPort=443 by default in handler; 0 means skip.
	wanted := map[string]bool{}
	if len(opt.Checks) == 0 {
		for _, n := range allCheckNames {
			wanted[n] = true
		}
	} else {
		for _, n := range opt.Checks {
			wanted[strings.TrimSpace(strings.ToLower(n))] = true
		}
	}

	out := make(map[string]Result, len(wanted))
	if wanted["p2p"] {
		out["p2p"] = CheckTCP(ctx, "p2p", opt.Host, opt.P2PPort, opt.Timeout)
	}
	if wanted["api_port"] {
		out["api_port"] = CheckTCP(ctx, "api_port", opt.Host, opt.APIPort, opt.Timeout)
	}
	if wanted["tls"] {
		if opt.TLSPort == 0 {
			out["tls"] = Result{Name: "tls", OK: false, Detail: "tls port disabled", Host: opt.Host}
		} else {
			out["tls"] = CheckTLS(ctx, opt.Host, opt.TLSPort, opt.Timeout)
		}
	}
	if wanted["rpc"] {
		out["rpc"] = CheckRPC(ctx, opt.Host, opt.APIPort, opt.UseHTTPS, opt.Timeout)
	}
	if wanted["telemetry"] {
		out["telemetry"] = CheckHTTP(ctx, "telemetry", opt.Host, opt.APIPort, "/api/v1/status", opt.UseHTTPS, opt.Timeout, false)
	}
	if wanted["dashboard"] {
		out["dashboard"] = CheckHTTP(ctx, "dashboard", opt.Host, opt.APIPort, "/", opt.UseHTTPS, opt.Timeout, true)
	}
	return out
}

// CheckTCP dials host:port.
func CheckTCP(ctx context.Context, name, host string, port int, timeout time.Duration) Result {
	p := port
	conn, err := dialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), timeout)
	if err != nil {
		return Result{Name: name, OK: false, Detail: err.Error(), Host: host, Port: &p}
	}
	_ = conn.Close()
	return Result{Name: name, OK: true, Detail: "connected", Host: host, Port: &p}
}

// CheckTLS performs a TLS handshake with system CA verification.
func CheckTLS(ctx context.Context, host string, port int, timeout time.Duration) Result {
	p := port
	raw, err := dialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), timeout)
	if err != nil {
		return Result{Name: "tls", OK: false, Detail: err.Error(), Host: host, Port: &p}
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return Result{Name: "tls", OK: false, Detail: "ssl: " + err.Error(), Host: host, Port: &p}
	}
	_ = conn.Close()
	return Result{Name: "tls", OK: true, Detail: "verified", Host: host, Port: &p}
}

// CheckRPC POSTs system_chain JSON-RPC.
func CheckRPC(ctx context.Context, host string, port int, useHTTPS bool, timeout time.Duration) Result {
	p := port
	scheme := "http"
	if useHTTPS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/rpc", scheme, host, port)
	body := `{"jsonrpc":"2.0","id":1,"method":"system_chain","params":[]}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return Result{Name: "rpc", OK: false, Detail: err.Error(), Host: host, Port: &p}
	}
	req.Header.Set("Content-Type", "application/json")
	client := httpClient(useHTTPS, timeout)
	resp, err := client.Do(req)
	if err != nil {
		return Result{Name: "rpc", OK: false, Detail: err.Error(), Host: host, Port: &p}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if resp.StatusCode >= 500 {
		return Result{Name: "rpc", OK: false, Detail: fmt.Sprintf("http %d", resp.StatusCode), Host: host, Port: &p}
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		// Live HTTP that is not JSON still counts as reachable surface for boosts.
		if resp.StatusCode >= 200 && resp.StatusCode < 500 {
			return Result{Name: "rpc", OK: true, Detail: fmt.Sprintf("http %d", resp.StatusCode), Host: host, Port: &p}
		}
		return Result{Name: "rpc", OK: false, Detail: "non-json response", Host: host, Port: &p}
	}
	if _, ok := data["result"]; ok {
		detail := fmt.Sprintf("chain=%v", data["result"])
		if len(detail) > 120 {
			detail = detail[:120]
		}
		return Result{Name: "rpc", OK: true, Detail: detail, Host: host, Port: &p}
	}
	if errObj, ok := data["error"]; ok {
		return Result{Name: "rpc", OK: false, Detail: fmt.Sprintf("rpc error: %v", errObj), Host: host, Port: &p}
	}
	return Result{Name: "rpc", OK: true, Detail: fmt.Sprintf("http %d", resp.StatusCode), Host: host, Port: &p}
}

// CheckHTTP GETs a path; if fingerprint is true, require dashboard markers.
func CheckHTTP(ctx context.Context, name, host string, port int, path string, useHTTPS bool, timeout time.Duration, fingerprint bool) Result {
	p := port
	scheme := "http"
	if useHTTPS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{Name: name, OK: false, Detail: err.Error(), Host: host, Port: &p}
	}
	client := httpClient(useHTTPS, timeout)
	resp, err := client.Do(req)
	if err != nil {
		return Result{Name: name, OK: false, Detail: err.Error(), Host: host, Port: &p}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if resp.StatusCode >= 400 {
		return Result{Name: name, OK: false, Detail: fmt.Sprintf("http %d", resp.StatusCode), Host: host, Port: &p}
	}
	if !fingerprint {
		return Result{Name: name, OK: true, Detail: fmt.Sprintf("http %d", resp.StatusCode), Host: host, Port: &p}
	}
	lower := strings.ToLower(string(raw))
	for _, m := range dashboardMarkers {
		if strings.Contains(lower, m) {
			return Result{Name: name, OK: true, Detail: "fingerprint ok", Host: host, Port: &p}
		}
	}
	return Result{Name: name, OK: false, Detail: "no dashboard fingerprint", Host: host, Port: &p}
}

func httpClient(useHTTPS bool, timeout time.Duration) *http.Client {
	tr := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialContext(ctx, network, address, timeout)
	}}
	if useHTTPS {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Timeout: timeout, Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if restricted, _ := req.Context().Value(publicTargetKey{}).(bool); restricted {
			return fmt.Errorf("redirects are not allowed for public reward probes")
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}}
}
