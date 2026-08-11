// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckTCPLocalListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	r := CheckTCP(context.Background(), "api_port", "127.0.0.1", port, 2*time.Second)
	if !r.OK {
		t.Fatalf("expected ok, got %+v", r)
	}
}

func TestCheckTCPRefused(t *testing.T) {
	r := CheckTCP(context.Background(), "p2p", "127.0.0.1", 1, 500*time.Millisecond)
	if r.OK {
		t.Fatalf("expected failure on closed port")
	}
}

func TestRunSelectedChecks(t *testing.T) {
	out := Run(context.Background(), Options{
		Host:    "127.0.0.1",
		P2PPort: 1,
		Checks:  []string{"p2p"},
		Timeout: 500 * time.Millisecond,
	})
	if _, ok := out["p2p"]; !ok {
		t.Fatalf("missing p2p: %v", out)
	}
	if out["p2p"].OK {
		t.Fatalf("expected p2p fail")
	}
}

func TestCheckHTTPFingerprint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><title>Quip Dashboard</title></html>"))
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().(*net.TCPAddr)
	r := CheckHTTP(context.Background(), "dashboard", "127.0.0.1", addr.Port, "/", false, 2*time.Second, true)
	if !r.OK {
		t.Fatalf("expected dashboard ok, got %+v", r)
	}
}
