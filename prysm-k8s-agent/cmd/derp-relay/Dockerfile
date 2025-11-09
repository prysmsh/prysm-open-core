# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache gcc musl-dev

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the DERP relay server (disable the forced full rebuild so cache can be reused)
RUN CGO_ENABLED=1 GOOS=linux go build -o derp-relay ./cmd/derp-relay

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates curl

WORKDIR /root/

# Create directories
RUN mkdir -p /app/static /app/certs

# Copy binary
COPY --from=builder /app/derp-relay /app/derp-relay

# Generate self-signed certificates for development
RUN apk add --no-cache openssl && \
    openssl req -x509 -newkey rsa:4096 -keyout /app/certs/key.pem -out /app/certs/cert.pem -days 365 -nodes \
        -subj "/C=US/ST=CA/L=San Francisco/O=Prysm/CN=localhost" && \
    apk del openssl

# Create basic static files for firewall evasion
RUN echo '<html><head><title>CDN Assets</title></head><body><h1>Content Delivery Network</h1><p>Asset delivery service.</p></body></html>' > /app/static/index.html

EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -k -f https://localhost:8443/health || exit 1

CMD ["/app/derp-relay"]
