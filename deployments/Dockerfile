# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:alpine AS builder
ENV GOTOOLCHAIN=auto
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/ai-gateway ./cmd/gateway

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /out/ai-gateway /app/ai-gateway
COPY configs/config.yaml /app/configs/config.yaml
COPY migrations /app/migrations
EXPOSE 8080
ENTRYPOINT ["/app/ai-gateway", "-config", "/app/configs/config.yaml"]
