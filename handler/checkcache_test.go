// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package handler

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"check.quip.network/checkcache"
)

// closedPort returns a port on loopback with nothing listening, so checks fail
// fast with a refused connection instead of waiting out the dial timeout.
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("close reserved port: %v", err)
	}
	return port
}

func call(t *testing.T, h http.HandlerFunc, path string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("X-Real-IP", "127.0.0.1")
	rec := httptest.NewRecorder()
	h(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return rec, body
}

func TestCheckPortReportsCacheMissThenHit(t *testing.T) {
	cache := checkcache.New()
	t.Cleanup(cache.Stop)
	h := NewCheckPort(cache)
	path := "/checkport?port=" + strconv.Itoa(closedPort(t))

	rec, body := call(t, h, path)
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("first request X-Cache: got %q, want MISS", got)
	}
	if body["cached"] != false {
		t.Errorf("first request cached field: got %v, want false", body["cached"])
	}

	rec, body = call(t, h, path)
	if got := rec.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("second request X-Cache: got %q, want HIT", got)
	}
	if body["cached"] != true {
		t.Errorf("second request cached field: got %v, want true", body["cached"])
	}
	if body["reachable"] != false {
		t.Errorf("cached body lost its result: %v", body)
	}
}

func TestCheckPortCachesPerPort(t *testing.T) {
	cache := checkcache.New()
	t.Cleanup(cache.Stop)
	h := NewCheckPort(cache)

	call(t, h, "/checkport?port="+strconv.Itoa(closedPort(t)))
	rec, _ := call(t, h, "/checkport?port="+strconv.Itoa(closedPort(t)))

	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("a different port must not hit the first port's entry: X-Cache %q", got)
	}
}

func TestCheckPortRejectsBadPortBeforeCaching(t *testing.T) {
	cache := checkcache.New()
	t.Cleanup(cache.Stop)
	h := NewCheckPort(cache)

	for _, path := range []string{"/checkport", "/checkport?port=0", "/checkport?port=abc"} {
		rec, _ := call(t, h, path)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", path, rec.Code)
		}
		if got := rec.Header().Get("X-Cache"); got != "" {
			t.Errorf("%s: rejected request must not carry an X-Cache header, got %q", path, got)
		}
	}
}

func TestCheckConnReportsCacheMissThenHit(t *testing.T) {
	cache := checkcache.New()
	t.Cleanup(cache.Stop)
	h := NewCheckConn(cache)
	path := "/checkconn?port=" + strconv.Itoa(closedPort(t))

	rec, body := call(t, h, path)
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("first request X-Cache: got %q, want MISS", got)
	}
	if body["cached"] != false {
		t.Errorf("first request cached field: got %v, want false", body["cached"])
	}

	rec, body = call(t, h, path)
	if got := rec.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("second request X-Cache: got %q, want HIT", got)
	}
	if body["cached"] != true {
		t.Errorf("second request cached field: got %v, want true", body["cached"])
	}
}

func TestCheckPortAndCheckConnDoNotShareEntries(t *testing.T) {
	cache := checkcache.New()
	t.Cleanup(cache.Stop)
	port := strconv.Itoa(closedPort(t))

	call(t, NewCheckPort(cache), "/checkport?port="+port)
	rec, _ := call(t, NewCheckConn(cache), "/checkconn?port="+port)

	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("the QUIC check must not read the TCP check's entry: X-Cache %q", got)
	}
}
