// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package internal

import (
	"net/http"
	"testing"
)

// A request that did not arrive from a trusted proxy must not be able to name
// its own client IP. That value is the rate-limit bucket key, the cache key and
// the dial target for /checkport and /checkconn, so honouring a caller-supplied
// header lets one request pick all three.
func TestForwardedForIsIgnoredFromUntrustedRemote(t *testing.T) {
	req := &http.Request{
		RemoteAddr: "203.0.113.7:51000",
		Header:     http.Header{},
	}
	req.Header.Set("X-Forwarded-For", "169.254.169.254")

	if got := ExtractClientIP(req); got != "203.0.113.7" {
		t.Fatalf("ExtractClientIP() = %q, want %q (header must not win over the connection)", got, "203.0.113.7")
	}
}

// Not every deployment puts the proxy in the same container. An operator who
// fronts this service from another host must be able to say so, or the loopback
// default would report the proxy's address as every caller's IP.
func TestForwardedForIsHonouredFromConfiguredProxy(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })

	if err := SetTrustedProxies([]string{"10.4.0.0/16"}); err != nil {
		t.Fatalf("SetTrustedProxies() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "10.4.1.9:51000",
		Header:     http.Header{},
	}
	req.Header.Set("X-Forwarded-For", "198.51.100.22")

	if got := ExtractClientIP(req); got != "198.51.100.22" {
		t.Fatalf("ExtractClientIP() = %q, want %q (configured proxy must be believed)", got, "198.51.100.22")
	}
}

func TestConfigureTrustedProxiesReadsCommaSeparatedEnv(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })
	t.Setenv("TRUSTED_PROXIES", "10.4.0.0/16, 192.0.2.5")

	if err := ConfigureTrustedProxiesFromEnv(); err != nil {
		t.Fatalf("ConfigureTrustedProxiesFromEnv() error = %v", err)
	}

	for _, addr := range []string{"10.4.1.9", "192.0.2.5"} {
		if !IsTrustedProxy(addr) {
			t.Errorf("IsTrustedProxy(%q) = false, want true", addr)
		}
	}
	if IsTrustedProxy("192.0.2.6") {
		t.Error(`IsTrustedProxy("192.0.2.6") = true, want false (outside the configured set)`)
	}
}

// A typo in configuration must stop the process, not quietly widen or narrow
// who gets believed.
func TestConfigureTrustedProxiesRejectsGarbage(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })
	t.Setenv("TRUSTED_PROXIES", "10.4.0.0/16,not-an-ip")

	if err := ConfigureTrustedProxiesFromEnv(); err == nil {
		t.Fatal("ConfigureTrustedProxiesFromEnv() error = nil, want an error")
	}
	if IsTrustedProxy("10.4.1.9") {
		t.Error(`IsTrustedProxy("10.4.1.9") = true, want false (a rejected config must apply nothing)`)
	}
}
