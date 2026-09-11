// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package handler

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"

	"check.quip.network/checkcache"
	"check.quip.network/internal"
	quipproto "check.quip.network/quip"
)

const (
	quicHandshakeTimeout  = 5 * time.Second
	statusResponseTimeout = 3 * time.Second
)

// NewCheckConn returns the GET /checkconn?port=PORT handler backed by cache.
//
// The target host is always the caller's own IP — this prevents the service
// from being used to scan arbitrary QUIC endpoints. Results are cached per
// caller IP and port, so a repeat request does not handshake again.
func NewCheckConn(cache *checkcache.Cache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		key := checkcache.Key{Kind: "quic", IP: host, Port: port}
		resp := cache.Get(r.Context(), key, func(ctx context.Context) checkcache.Result {
			return dialQUIP(ctx, host, port)
		})
		writeCached(w, resp)
	}
}

// dialQUIP performs a QUIC handshake with the QUIP ALPN and asks the peer for
// a status response.
func dialQUIP(ctx context.Context, host string, port int) checkcache.Result {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	tlsCfg := &tls.Config{
		NextProtos:         []string{quipproto.ALPN},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	}
	quicCfg := &quic.Config{EnableDatagrams: true}

	dialCtx, cancel := context.WithTimeout(ctx, quicHandshakeTimeout)
	defer cancel()

	start := time.Now()
	conn, err := quic.DialAddr(dialCtx, addr, tlsCfg, quicCfg)
	handshakeMs := time.Since(start).Milliseconds()
	if err != nil {
		return checkcache.Result{OK: false, Body: map[string]any{
			"host":  host,
			"port":  port,
			"quip":  false,
			"error": err.Error(),
		}}
	}
	defer conn.CloseWithError(0, "check complete")

	// Send STATUS_REQUEST datagram.
	statusReq := quipproto.BuildStatusRequest(1)
	if err := conn.SendDatagram(statusReq); err != nil {
		return checkcache.Result{OK: false, Body: map[string]any{
			"host":            host,
			"port":            port,
			"quip":            true,
			"handshake_ms":    handshakeMs,
			"status_response": false,
			"error":           "failed to send datagram: " + err.Error(),
		}}
	}

	// Wait for STATUS_RESPONSE.
	statusCtx, statusCancel := context.WithTimeout(ctx, statusResponseTimeout)
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

	return checkcache.Result{OK: true, Body: map[string]any{
		"host":            host,
		"port":            port,
		"quip":            true,
		"handshake_ms":    handshakeMs,
		"status_response": gotStatus,
	}}
}
