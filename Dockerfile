# Stage 1: Build the application using native builder platform
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

# Set the working directory
WORKDIR /app

# Copy go.mod and go.sum to download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Target OS and architecture passed by Buildx
ARG TARGETOS
ARG TARGETARCH

# Build statically linked binary natively targeting TARGETOS and TARGETARCH
# -ldflags="-w -s" strips debugging information
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -a -ldflags="-w -s" -o /go-admin-tool ./cmd/server

# Stage 2: Create the minimal hardened final image
FROM alpine:3.21

# Metadata build arguments
ARG VERSION="dev"
ARG REVISION=""
ARG CREATED=""

# Standard OCI image annotations
LABEL org.opencontainers.image.title="api_executor" \
      org.opencontainers.image.description="High-performance, secure REST & MCP server for executing predefined administrative tasks with audit trails, RBAC, and Prometheus metrics" \
      org.opencontainers.image.authors="Jean-Marc Renouard" \
      org.opencontainers.image.url="https://github.com/jmrenouard/api_executor" \
      org.opencontainers.image.documentation="https://github.com/jmrenouard/api_executor#readme" \
      org.opencontainers.image.source="https://github.com/jmrenouard/api_executor" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.vendor="Jean-Marc Renouard" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"

# Install essential runtime utilities for healthchecks and TLS verification
RUN apk add --no-cache ca-certificates curl tzdata

# Set the working directory
WORKDIR /app

# Add a non-root user with deterministic UID/GID for security
RUN addgroup -g 10001 -S appgroup && adduser -u 10001 -S appuser -G appgroup

# Copy the binary from the builder stage
COPY --chown=10001:10001 --from=builder /go-admin-tool .

# Copy configuration, declarative plugins, and static files
COPY --chown=10001:10001 config.yaml .
COPY --chown=10001:10001 --from=builder /app/plugins ./plugins
COPY --chown=10001:10001 web ./web

# Create secure file directory, data directory, and TLS certificate directory owned by appuser
RUN mkdir -p /var/log/secure_files /app/certs /app/data && chown -R appuser:appgroup /app /var/log/secure_files

# Switch to the non-root user (appuser UID/GID 10001:10001)
USER 10001:10001

# Expose the application port
EXPOSE 8080

# Healthcheck probe verifying API availability
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-check-certificate -qO- https://127.0.0.1:8080/metrics > /dev/null || exit 1

# This is the command to run the application
ENTRYPOINT ["./go-admin-tool"]
