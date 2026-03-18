// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package handler

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"check.quip.network/internal"
)

const (
	tcpConnectTimeout = 5 * time.Second
	tcpReadTimeout    = 1 * time.Second
	maxBannerBytes    = 4
)

// CheckPort handles GET /checkport?host=HOST&port=PORT.
func CheckPort(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	portStr := r.URL.Query().Get("port")

	if host == "" {
		writeError(w, http.StatusBadRequest, "host parameter required")
		return
	}
	if portStr == "" {
		writeError(w, http.StatusBadRequest, "port parameter required")
		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		writeError(w, http.StatusBadRequest, "port must be 1-65535")
		return
	}

	if _, err := internal.ResolveAndValidate(host); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, tcpConnectTimeout)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"host":      host,
			"port":      port,
			"reachable": false,
			"error":     err.Error(),
		})
		return
	}
	defer conn.Close()

	// Try to read first few bytes (banner grab).
	conn.SetReadDeadline(time.Now().Add(tcpReadTimeout))
	buf := make([]byte, maxBannerBytes)
	n, _ := conn.Read(buf)

	resp := map[string]any{
		"host":      host,
		"port":      port,
		"reachable": true,
	}
	if n > 0 {
		resp["bytes"] = hex.EncodeToString(buf[:n])
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{
		"error": fmt.Sprintf("%s", msg),
	})
}
