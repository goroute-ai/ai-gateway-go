# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:alpine AS builder
ENV GOTOOLCHAIN=auto
WORKDIR /src
COPY go.mod go.sum ./
COPY tests/fixtures/mock-upstream ./tests/fixtures/mock-upstream
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/mock-upstream ./tests/fixtures/mock-upstream

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /out/mock-upstream /app/mock-upstream
EXPOSE 8443
ENTRYPOINT ["/app/mock-upstream"]
