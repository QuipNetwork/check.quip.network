# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Network diagnostic service for the QUIP P2P network. Provides IP lookup, TCP port checking, hostname-to-IP matching, and QUIC/QUIP protocol connectivity verification. Deployed as a multi-arch Docker container (Flux, Akash, any cloud). Aggressive rate limiting protects against abuse.

## Commands

```bash
# Setup
go mod tidy

# Build
go build .
go vet ./...

# Docker
docker build -t check-quip .
docker buildx build --platform linux/amd64,linux/arm64 -t check-quip .

# Run
docker run -d -p 8080:8080 check-quip
# Or: PORT=9090 go run .

# Integration tests (requires running container)
docker run -d --name check-quip-test -p 8080:8080 check-quip
CHECK_QUIP_URL=http://localhost:8080 go test ./tests/ -v -count=1
docker stop check-quip-test && docker rm check-quip-test

# Makefile shortcuts
make build       # docker build
make buildx      # multi-arch docker buildx
make run         # docker run
make test        # build, run, test, clean
make vet         # go vet
make clean       # stop and remove container
```

## Architecture

### Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Health check (not rate limited) |
| `GET /ip` | Returns caller's public IP |
| `GET /checkport?port=P` | TCP port reachability on caller's own IP + banner grab |
| `GET /checkhostname?hostname=H` | Checks if caller IP matches hostname DNS resolution |
| `GET /checkconn?port=P` | QUIC/QUIP connectivity check on caller's own IP (ALPN `quip-v1`) |
| `GET /probe?host=H` | Host-targeted reward checks (p2p, api_port, tls, rpc, telemetry, dashboard), cached 24h per host |

### File Structure

| File | Purpose |
|------|---------|
| `main.go` | Entry point, stdlib router, middleware wiring |
| `handler/health.go` | GET /health |
| `handler/ip.go` | GET /ip |
| `handler/checkport.go` | GET /checkport — TCP connect + banner grab |
| `handler/checkhostname.go` | GET /checkhostname — hostname-to-IP match |
| `handler/checkconn.go` | GET /checkconn — QUIC/QUIP protocol check |
| `handler/probe.go` | GET /probe — request parsing, host validation |
| `probe/probe.go` | The six reward checks (source of truth for check semantics) |
| `probe/cache.go` | 24h per-host probe cache + response envelope |
| `quip/protocol.go` | QUIP wire format constants + STATUS_REQUEST builder |
| `internal/iputil.go` | IP extraction (XFF, X-Real-IP, RemoteAddr), private IP validation |
| `ratelimit/ratelimit.go` | Sliding window (5 req/min) + escalating bans |
| `openapi.yaml` | OpenAPI 3.1 specification |
| `tests/integration_test.go` | 16 integration tests against live container |

### Rate Limiting

- 5 requests/minute per IP (sliding window), all endpoints except /health
- Escalating bans: 1st violation → 1hr, 2nd → 1 day, 3rd+ → 1 week
- Background cleanup prunes idle entries every 10 minutes

### Probe Caching

`/probe` runs at most one real probe per target host per 24 hours. Later
requests return the stored result with `cached: true` and an `X-Cache: HIT`
header. The cache key is the normalized host alone, not the query parameters,
so varying ports or checks cannot force a fresh probe; `params_used` in the
response reports the options the stored probe ran with. The per-host lock also
collapses concurrent first-requests into a single outbound probe.

Unknown `checks` names are rejected with 400 before any probe runs, so a
request cannot reach the cache with a selection that matches nothing.

Failures are cached for the full 24 hours, the same as successes. A shorter TTL
for failures would let a caller re-probe any host on demand by making the probe
fail. The one result not stored is an empty set, which means the requested
check names matched nothing.

### Security: Self-Check Only

`/checkport` and `/checkconn` always target the caller's own IP (derived from the connection). No `host` parameter is accepted — this prevents the service from being used as a port scanner or QUIC probe against arbitrary targets.

## Docker Registries

| Registry | Image |
|----------|-------|
| Docker Hub | `carback1/check-quip-network:latest` / `:1.0.0` |
| GitLab | `registry.gitlab.com/piqued/check.quip.network:latest` / `:1.0.0` |

## Key Dependencies

- `github.com/quic-go/quic-go` — QUIC transport for /checkconn
- Go stdlib `net/http` — HTTP server with Go 1.22+ method-aware routing

## License

AGPL-3.0-or-later
