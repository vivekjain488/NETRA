# NETRA backend image.
#
# Multi-stage so the runtime layer carries no toolchain, and non-root by
# default: the control plane has no reason to run as uid 0.

FROM golang:1.25-alpine AS build
WORKDIR /src

# Dependency layer, cached independently of source changes.
#
# The cache mounts matter more than they look: without them every image build
# re-downloads the module set and recompiles the standard library, which turns
# a one-line change into a multi-minute rebuild and pushes developers off the
# documented path.
COPY backend/go.mod backend/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY backend/ ./
ARG VERSION=0.1.0-dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w \
      -X github.com/netra/backend/internal/version.Version=${VERSION} \
      -X github.com/netra/backend/internal/version.Commit=${COMMIT} \
      -X github.com/netra/backend/internal/version.BuildTime=${BUILD_TIME}" \
    -o /out/netrad ./cmd/netrad

FROM alpine:3.21 AS runtime
RUN apk add --no-cache ca-certificates wget \
 && adduser -D -u 10001 netra
COPY --from=build /out/netrad /usr/local/bin/netrad
USER netra
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=5 \
    CMD wget -qO- http://127.0.0.1:8080/api/v1/health >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/netrad"]
