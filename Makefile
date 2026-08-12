# SPDX-License-Identifier: AGPL-3.0-or-later

IMAGE := check-quip
CONTAINER := check-quip-test
PORT := 8080
PLATFORMS := linux/amd64,linux/arm64

# The TLS image is what runs on Flux: nginx terminating TLS in front of the Go
# service, with certs from dnsimple-certifier. Flux is amd64-only, so this one
# is deliberately single-arch.
TLS_IMAGE := check-quip-tls
TLS_PLATFORM := linux/amd64
CERTIFIER_REF ?= v0.1.0

.PHONY: build run test clean buildx vet certifier-src build-tls

build:
	docker build -t $(IMAGE) .

buildx:
	docker buildx build --platform $(PLATFORMS) -t $(IMAGE) .

certifier-src:
	CERTIFIER_REF=$(CERTIFIER_REF) ./scripts/fetch-certifier.sh

# --provenance/--sbom off: buildx otherwise emits a manifest list carrying an
# extra unknown/unknown attestation entry. Flux pins images by digest, so keep
# the pushed artifact a plain single-platform manifest.
build-tls: certifier-src
	docker build --platform $(TLS_PLATFORM) --provenance=false --sbom=false \
		-f Dockerfile.tls -t $(TLS_IMAGE) .

run:
	docker run -d --name $(CONTAINER) -p $(PORT):8080 $(IMAGE)

test: run
	sleep 2
	CHECK_QUIP_URL=http://localhost:$(PORT) go test ./tests/ -v -count=1; \
	ret=$$?; \
	$(MAKE) clean; \
	exit $$ret

vet:
	go vet ./...

clean:
	-docker stop $(CONTAINER) 2>/dev/null
	-docker rm $(CONTAINER) 2>/dev/null
