// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024 QUIP Contributors

package main

import (
	"log"
	"net/http"
	"os"

	"check.quip.network/handler"
	"check.quip.network/ratelimit"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	limiter := ratelimit.New()
	defer limiter.Stop()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", handler.Health)
	mux.HandleFunc("GET /ip", handler.IP)
	mux.HandleFunc("GET /checkport", handler.CheckPort)
	mux.HandleFunc("GET /checkconn", handler.CheckConn)

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: limiter.Middleware(mux),
	}

	log.Printf("check.quip.network listening on :%s", port)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
