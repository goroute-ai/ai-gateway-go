# syntax=docker/dockerfile:1
# Note: Frontend Operator UI assets are compiled and verified via 'make ui-build'
# and embedded directly into the Go binary from internal/ui/dist via go:embed.
# This keeps the container build fast, deterministic, reproducible, and free of Node.js toolchain overhead.
FROM --platform=$BUILDPLATFORM golang:alpine AS builder
ENV GOTOOLCHAIN=auto
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=v1.21.0
ARG COMMIT=dev
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath \
  -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}" \
  -o /out/ai-gateway ./cmd/gateway

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="GoRoute AI Gateway" \
      org.opencontainers.image.description="Ultra-fast, lightweight AI Gateway, MCP Hub, and A2A Router in 100% Pure Go with Embedded Operator Web UI" \
      org.opencontainers.image.url="https://github.com/goroute-ai/ai-gateway-go" \
      org.opencontainers.image.source="https://github.com/goroute-ai/ai-gateway-go" \
      org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /app
COPY --from=builder /out/ai-gateway /app/ai-gateway
COPY configs/config.yaml /app/configs/config.yaml
COPY migrations /app/migrations
EXPOSE 8080
ENTRYPOINT ["/app/ai-gateway"]
CMD ["-config", "/app/configs/config.yaml"]
