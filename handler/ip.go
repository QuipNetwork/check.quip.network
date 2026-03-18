// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package handler

import (
	"encoding/json"
	"net/http"

	"check.quip.network/internal"
)

// IP handles GET /ip.
func IP(w http.ResponseWriter, r *http.Request) {
	ip := internal.ExtractClientIP(r)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"ip": ip,
	})
}
