// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package main

import (
	"log"
	"net/http"
	"os"

	"check.quip.network/checkcache"
	"check.quip.network/handler"
	"check.quip.network/probe"
	"check.quip.network/ratelimit"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	limiter := ratelimit.New()
	defer limiter.Stop()

	// One real probe per target host per day; repeats are served from cache.
	probeCache := probe.NewCache()
	defer probeCache.Stop()

	// Self-targeted checks are cached per caller IP and port: an hour for a
	// reachable result, a minute for a failure so operators see a fix.
	selfCheckCache := checkcache.New()
	defer selfCheckCache.Stop()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", handler.Health)
	mux.HandleFunc("GET /ip", handler.IP)
	mux.HandleFunc("GET /checkport", handler.NewCheckPort(selfCheckCache))
	mux.HandleFunc("GET /checkconn", handler.NewCheckConn(selfCheckCache))
	mux.HandleFunc("GET /checkhostname", handler.CheckHostname)
	// Host-targeted reward probes (source of truth for node-quest boosts).
	// Rate-limited by the global limiter and cached per target host for 24h.
	mux.HandleFunc("GET /probe", handler.NewProbe(probeCache))

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: limiter.Middleware(mux),
	}

	log.Printf("check.quip.network listening on :%s", port)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
