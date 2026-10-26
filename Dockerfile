# Stage 1: Build the application
FROM golang:1.24-alpine AS builder

# Set the working directory
WORKDIR /app

# Copy go.mod and go.sum to download dependencies
COPY go.mod go.sum ./

# Copy the rest of the source code
COPY . .

# First, get the dependencies for the project, including swag
RUN go mod tidy
RUN go install github.com/swaggo/swag/cmd/swag@latest

# Generate Swagger docs
RUN swag init -g cmd/server/main.go

# Build the application
# -ldflags="-w -s" strips debugging information
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags="-w -s" -o /go-admin-tool ./cmd/server

# Stage 2: Create the final image
FROM alpine:latest

# Set the working directory
WORKDIR /app

# Add a non-root user for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy the binary from the builder stage
COPY --from=builder /go-admin-tool .

# Copy configuration, declarative plugins, and static files
COPY config.yaml .
COPY --from=builder /app/plugins ./plugins
COPY --chown=appuser:appgroup web ./web

# Create secure file directory and TLS certificate directory owned by appuser
RUN mkdir -p /var/log/secure_files /app/certs && chown -R appuser:appgroup /app /var/log/secure_files

# Switch to the non-root user
USER appuser

# Expose the application port
EXPOSE 8080

# This is the command to run the application
ENTRYPOINT ["./go-admin-tool"]
