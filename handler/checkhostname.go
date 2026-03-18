// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package handler

import (
	"encoding/json"
	"net"
	"net/http"

	"check.quip.network/internal"
)

// CheckHostname handles GET /checkhostname?hostname=HOSTNAME.
// Returns whether the caller's public IP matches the DNS resolution
// of the provided hostname.
func CheckHostname(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("hostname")
	if hostname == "" {
		writeError(w, http.StatusBadRequest, "hostname parameter required")
		return
	}

	clientIP := internal.ExtractClientIP(r)

	addrs, err := net.LookupIP(hostname)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"hostname":  hostname,
			"client_ip": clientIP,
			"match":     false,
			"error":     "DNS lookup failed: " + err.Error(),
		})
		return
	}

	resolvedIPs := make([]string, len(addrs))
	match := false
	for i, addr := range addrs {
		resolvedIPs[i] = addr.String()
		if addr.String() == clientIP {
			match = true
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"hostname":     hostname,
		"client_ip":    clientIP,
		"resolved_ips": resolvedIPs,
		"match":        match,
	})
}
