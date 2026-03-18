# SPDX-License-Identifier: AGPL-3.0-or-later

IMAGE := check-quip
CONTAINER := check-quip-test
PORT := 8080
PLATFORMS := linux/amd64,linux/arm64

.PHONY: build run test clean buildx vet

build:
	docker build -t $(IMAGE) .

buildx:
	docker buildx build --platform $(PLATFORMS) -t $(IMAGE) .

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
