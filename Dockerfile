# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024 QUIP Contributors

FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /app
COPY go.mod go.sum ./
RUN GOTOOLCHAIN=auto go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /check-quip .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /check-quip /check-quip
EXPOSE 8080
ENTRYPOINT ["/check-quip"]
