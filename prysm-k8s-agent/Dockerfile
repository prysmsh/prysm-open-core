FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the agent binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o prysm-agent ./cmd/agent

# Final stage - minimal runtime image
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    curl \
    ca-certificates \
    && rm -rf /var/cache/apk/*

# Install kubectl
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
    && chmod +x kubectl \
    && mv kubectl /usr/local/bin/

# Create non-root user
RUN addgroup -g 1001 prysm \
    && adduser -D -u 1001 -G prysm prysm

# Create necessary directories
RUN mkdir -p /var/log/kubeaccess \
    /var/lib/prysm-agent \
    && chown -R prysm:prysm /var/log/kubeaccess /var/lib/prysm-agent

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /app/prysm-agent .

# Copy configuration templates
COPY config/ ./config/

# Set up environment
ENV CLUSTER_ID=""
ENV AGENT_TOKEN=""
ENV ORGANIZATION_ID=1
ENV BACKEND_URL="http://kubeaccess-backend:8080"
ENV REGION="us-east-1"
ENV DERP_SERVER="wss://derp.kubeaccess.com/derp"
ENV LOG_LEVEL="info"

# Logging environment variables
ENV ENABLE_LOGGING=true
ENV LOG_INGESTION_URL=""
ENV USE_PRIVATE_LINK=false
ENV LOG_SOURCES="pod,event,system"
ENV LOG_LEVELS="info,warn,error,fatal"
ENV LOG_BATCH_SIZE=100
ENV LOG_COLLECTION_INTERVAL=30s

# Health check ensures the agent process is still running
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep prysm-agent >/dev/null || exit 1

# Switch to non-root user for security
USER prysm

EXPOSE 8080

CMD ["./prysm-agent"]
