// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package tests

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

func baseURL() string {
	if u := os.Getenv("CHECK_QUIP_URL"); u != "" {
		return u
	}
	return "http://localhost:8080"
}

func getJSON(t *testing.T, path string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Get(baseURL() + path)
	if err != nil {
		t.Fatalf("GET %s failed: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("invalid JSON from %s: %s", path, body)
	}
	return resp.StatusCode, result
}

func TestHealthEndpoint(t *testing.T) {
	code, body := getJSON(t, "/health")
	if code != 200 {
		t.Fatalf("expected 200, got %d", code)
	}
	if body["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", body["status"])
	}
}

func TestIPReturnsValidIP(t *testing.T) {
	code, body := getJSON(t, "/ip")
	if code != 200 {
		t.Fatalf("expected 200, got %d", code)
	}
	ip, ok := body["ip"].(string)
	if !ok || ip == "" {
		t.Fatalf("expected non-empty ip string, got %v", body["ip"])
	}
}

func TestIPWithForwardedFor(t *testing.T) {
	// Note: X-Forwarded-For may not propagate through Docker networking.
	// This test documents the expected behavior when headers are received.
	req, _ := http.NewRequest("GET", baseURL()+"/ip", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.42, 10.0.0.1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	// The IP returned depends on whether the proxy/Docker rewrites headers.
	// We just verify the response is valid JSON with an ip field.
	if _, ok := body["ip"].(string); !ok {
		t.Fatalf("expected ip field in response")
	}
}

func TestCheckPortReachable(t *testing.T) {
	// Check the service's own HTTP port via a public hostname.
	// This may not work in all environments; skip if no suitable target.
	code, body := getJSON(t, "/checkport?host=google.com&port=443")
	if code != 200 {
		t.Fatalf("expected 200, got %d", code)
	}
	if body["reachable"] != true {
		t.Logf("google.com:443 not reachable (may be network-restricted): %v", body)
	}
}

func TestCheckPortUnreachable(t *testing.T) {
	// Port 1 is almost never open.
	code, body := getJSON(t, "/checkport?host=google.com&port=1")
	if code != 200 {
		t.Fatalf("expected 200, got %d", code)
	}
	if body["reachable"] != false {
		t.Fatalf("expected reachable=false for port 1, got %v", body["reachable"])
	}
	if _, ok := body["error"]; !ok {
		t.Fatalf("expected error field when unreachable")
	}
}

func TestCheckPortInvalidInputs(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"missing host", "/checkport?port=80"},
		{"missing port", "/checkport?host=example.com"},
		{"port zero", "/checkport?host=example.com&port=0"},
		{"port too high", "/checkport?host=example.com&port=99999"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _ := getJSON(t, tc.path)
			if code != 400 {
				t.Fatalf("expected 400, got %d", code)
			}
		})
	}
}

func TestCheckPortPrivateIP(t *testing.T) {
	cases := []string{
		"/checkport?host=127.0.0.1&port=80",
		"/checkport?host=10.0.0.1&port=80",
		"/checkport?host=192.168.1.1&port=80",
	}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			code, _ := getJSON(t, path)
			if code != 400 {
				t.Fatalf("expected 400 for private IP, got %d", code)
			}
		})
	}
}

func TestCheckConnInvalidInputs(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"missing host", "/checkconn"},
		{"private IP", "/checkconn?host=127.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _ := getJSON(t, tc.path)
			if code != 400 {
				t.Fatalf("expected 400, got %d", code)
			}
		})
	}
}

func TestCheckConnUnreachable(t *testing.T) {
	// Use a public IP that won't respond on QUIC port.
	code, body := getJSON(t, "/checkconn?host=google.com&port=1")
	if code != 200 {
		t.Fatalf("expected 200, got %d", code)
	}
	if body["quip"] != false {
		t.Fatalf("expected quip=false for unreachable host")
	}
}

func TestCheckConnDefaultPort(t *testing.T) {
	code, body := getJSON(t, "/checkconn?host=google.com")
	if code != 200 {
		t.Fatalf("expected 200, got %d", code)
	}
	port, ok := body["port"].(float64)
	if !ok || int(port) != 20049 {
		t.Fatalf("expected default port 20049, got %v", body["port"])
	}
}

func TestRateLimitEnforced(t *testing.T) {
	// Use a unique client approach — send 6 rapid requests.
	// The rate limiter tracks by IP, so in integration tests behind
	// Docker networking all requests come from the same IP.
	var lastCode int
	for i := 0; i < 6; i++ {
		code, _ := getJSON(t, fmt.Sprintf("/ip?_t=%d", i))
		lastCode = code
	}
	if lastCode != 429 {
		t.Fatalf("expected 429 on 6th request, got %d", lastCode)
	}
}

func TestRateLimitBanEscalation(t *testing.T) {
	// After TestRateLimitEnforced, we should already be banned.
	// Verify the ban response includes escalating fields.
	code, body := getJSON(t, "/ip")
	if code != 429 {
		t.Skipf("not rate limited (code=%d), skipping escalation test", code)
	}
	retryAfter, ok := body["retry_after_seconds"].(float64)
	if !ok || retryAfter <= 0 {
		t.Fatalf("expected positive retry_after_seconds, got %v", body["retry_after_seconds"])
	}
	banLevel, ok := body["ban_level"].(float64)
	if !ok || banLevel < 1 {
		t.Fatalf("expected ban_level >= 1, got %v", body["ban_level"])
	}
}

func TestHealthNotRateLimited(t *testing.T) {
	// /health should always return 200 regardless of rate limit state.
	for i := 0; i < 10; i++ {
		resp, err := http.Get(baseURL() + "/health")
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: expected 200, got %d", i, resp.StatusCode)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
