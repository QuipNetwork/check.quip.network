// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/http"
	"strconv"
	"time"

	"check.quip.network/checkcache"
	"check.quip.network/internal"
)

const (
	tcpConnectTimeout = 5 * time.Second
	tcpReadTimeout    = 1 * time.Second
	maxBannerBytes    = 4
)

// NewCheckPort returns the GET /checkport?port=PORT handler backed by cache.
//
// The target host is always the caller's own IP — this prevents the service
// from being used as an internet port scanner. Results are cached per caller IP
// and port, so a repeat request does not dial again.
func NewCheckPort(cache *checkcache.Cache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := internal.ExtractClientIP(r)
		portStr := r.URL.Query().Get("port")

		if portStr == "" {
			writeError(w, http.StatusBadRequest, "port parameter required")
			return
		}

		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			writeError(w, http.StatusBadRequest, "port must be 1-65535")
			return
		}

		key := checkcache.Key{Kind: "tcp", IP: host, Port: port}
		resp := cache.Get(r.Context(), key, func(context.Context) checkcache.Result {
			return dialTCP(host, port)
		})
		writeCached(w, resp)
	}
}

// dialTCP connects to host:port and grabs the first few bytes of any banner.
func dialTCP(host string, port int) checkcache.Result {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, tcpConnectTimeout)
	if err != nil {
		return checkcache.Result{OK: false, Body: map[string]any{
			"host":      host,
			"port":      port,
			"reachable": false,
			"error":     err.Error(),
		}}
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(tcpReadTimeout))
	buf := make([]byte, maxBannerBytes)
	n, _ := conn.Read(buf)

	body := map[string]any{
		"host":      host,
		"port":      port,
		"reachable": true,
	}
	if n > 0 {
		body["bytes"] = hex.EncodeToString(buf[:n])
	}
	return checkcache.Result{OK: true, Body: body}
}

// writeCached emits a cached check result with the same cache metadata shape
// /probe uses: fields in the body and X-Cache headers alongside them.
func writeCached(w http.ResponseWriter, resp checkcache.Response) {
	body := make(map[string]any, len(resp.Body)+3)
	maps.Copy(body, resp.Body)
	body["cached"] = resp.Cached
	body["cached_at"] = resp.CachedAt.UTC().Format(time.RFC3339)
	body["expires_at"] = resp.ExpiresAt.UTC().Format(time.RFC3339)

	w.Header().Set("Content-Type", "application/json")
	if resp.Cached {
		w.Header().Set("X-Cache", "HIT")
	} else {
		w.Header().Set("X-Cache", "MISS")
	}
	w.Header().Set("X-Cache-Cached-At", resp.CachedAt.UTC().Format(time.RFC3339))
	w.Header().Set("X-Cache-Expires", resp.ExpiresAt.UTC().Format(time.RFC3339))
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": fmt.Sprintf("%s", msg),
	})
}
