// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package handler

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"

	"check.quip.network/internal"
	quipproto "check.quip.network/quip"
)

const (
	quicHandshakeTimeout  = 5 * time.Second
	statusResponseTimeout = 3 * time.Second
)

// CheckConn handles GET /checkconn?port=PORT.
// The target host is always the caller's own IP — this prevents
// the service from being used to scan arbitrary QUIC endpoints.
func CheckConn(w http.ResponseWriter, r *http.Request) {
	host := internal.ExtractClientIP(r)
	portStr := r.URL.Query().Get("port")

	port := quipproto.DefaultPort
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			writeError(w, http.StatusBadRequest, "port must be 1-65535")
			return
		}
		port = p
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	tlsCfg := &tls.Config{
		NextProtos:         []string{quipproto.ALPN},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	}
	quicCfg := &quic.Config{
		EnableDatagrams: true,
	}

	ctx, cancel := context.WithTimeout(
		r.Context(), quicHandshakeTimeout,
	)
	defer cancel()

	start := time.Now()
	conn, err := quic.DialAddr(ctx, addr, tlsCfg, quicCfg)
	handshakeMs := time.Since(start).Milliseconds()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"host":  host,
			"port":  port,
			"quip":  false,
			"error": err.Error(),
		})
		return
	}
	defer conn.CloseWithError(0, "check complete")

	// Send STATUS_REQUEST datagram.
	statusReq := quipproto.BuildStatusRequest(1)
	if err := conn.SendDatagram(statusReq); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"host":         host,
			"port":         port,
			"quip":         true,
			"handshake_ms": handshakeMs,
			"status_response": false,
			"error":        "failed to send datagram: " + err.Error(),
		})
		return
	}

	// Wait for STATUS_RESPONSE.
	statusCtx, statusCancel := context.WithTimeout(
		r.Context(), statusResponseTimeout,
	)
	defer statusCancel()

	gotStatus := false
	for {
		data, err := conn.ReceiveDatagram(statusCtx)
		if err != nil {
			break
		}
		if quipproto.IsStatusResponse(data) {
			gotStatus = true
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"host":            host,
		"port":            port,
		"quip":            true,
		"handshake_ms":    handshakeMs,
		"status_response": gotStatus,
	})
}
