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
| `internal/iputil.go` | Client IP extraction and the trusted-proxy gate on forwarding headers |
| `checkcache/cache.go` | Per-IP-and-port cache for /checkport and /checkconn |
| `ratelimit/ratelimit.go` | Token bucket mechanics (burst 10, refill 2/s) |
| `ratelimit/policy.go` | Ban ladder and violation decay |
| `openapi.yaml` | OpenAPI 3.1 specification |
| `tests/integration_test.go` | 16 integration tests against live container |

### Rate Limiting

Token bucket per IP, all endpoints except /health.

- Bucket holds 10 requests and refills at 2 per second. A client may burst 10
  requests, then sustain 2 per second forever. The node app checks two ports
  per second, so that pattern must never trip the limiter.
- A request arriving at an empty bucket is a violation and earns a ban.
- Ban ladder: 30 seconds, then 2 minutes, then 5 minutes for every violation
  after that. The 5 minute ceiling is `maxBanDuration`.
- Violations decay after 15 minutes without a new violation, so the ladder
  reflects current behavior rather than a permanent record. The decay window
  must stay longer than the longest ban. If a client could outlast it by
  serving the ban, every violation would be a first violation.
- The ladder and the decay window live in `ratelimit/policy.go`, apart from
  the bucket mechanics in `ratelimit/ratelimit.go`.
- Background cleanup prunes idle entries every 10 minutes.

### Self-Check Caching

`/checkport` and `/checkconn` cache their results per caller IP and port. A
reachable result stands for 1 hour. A failure stands for 1 minute.

The split TTL exists because the usual caller of a failing check is an operator
fixing a firewall and retrying. A 1 hour failure cache would make that operator
wait an hour to see the fix, and 1 minute still collapses a retry storm.

`/probe` takes the opposite rule and caches failures for the full 24 hours. A
probe accepts another host as its target. A short failure TTL there would let a
caller re-probe any host on demand by making the probe fail. That attack does
not apply to a self-check.

The cache key includes the check kind, so the TCP and QUIC checks never read
each other's entries. The per-key lock collapses concurrent first-requests into
a single outbound dial.

Because the key uses the caller's public IP, machines behind one NAT share an
entry for the same port.

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

### Security: Client IP and Trusted Proxies

One derived value is the rate-limit bucket key, the self-check cache key and the
dial target for `/checkport` and `/checkconn`. A caller who can name that value
picks all three: a fresh bucket, an arbitrary cache entry, and where the service
dials — which would undo the self-check-only rule above.

So `X-Forwarded-For` and `X-Real-IP` are honoured **only** when the request
arrived from a trusted proxy. Otherwise the connection address wins.

- Loopback is always trusted, which covers the deployed shape: nginx terminates
  TLS in front of the service and proxies to it over `127.0.0.1`.
- `TRUSTED_PROXIES` extends that for deployments whose proxy is on another host.
  It takes a comma-separated list of CIDRs or bare addresses, e.g.
  `TRUSTED_PROXIES=10.4.0.0/16,192.0.2.5`. Unset means loopback only.
- An unparseable entry is fatal at startup. Guessing is worse than not starting,
  because the wrong answer silently mis-keys the limiter and the cache.

A proxy in front of this service must **overwrite** both headers rather than
append to them. Appending (`$proxy_add_x_forwarded_for`) leaves the caller's
value first in the list, and the first entry is what gets read.

## Deployment

⚠ **The image CI builds is not the image that runs in production.**

CI builds the plain `Dockerfile` — a distroless single binary on `:8080` with no
TLS. Nothing deploys it; it is a build and test artifact.

`check.quip.network` runs on Flux from a **separate image** that wraps this
service in nginx for TLS, built from the **`deploy/flux`** branch, which carries
`Dockerfile.tls`, `nginx.conf`, `entrypoint.sh` and `flux-app-spec.json`. That
branch merges `main` when a release ships. Deployment packaging is maintained
there, not here.

If you are about to deploy this service, start from `deploy/flux`, not `main`.

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
