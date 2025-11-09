# Open-core Dockerfile for Prysm Backend
# This builds the backend without enterprise features

FROM golang:1.24-alpine AS builder

ARG VERSION=dev
ARG BUILD_TAGS="!enterprise"

RUN apk add --no-cache git ca-certificates

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build without enterprise features  
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -tags "${BUILD_TAGS}" \
    -o prysm-backend ./cmd/api

FROM alpine:latest

RUN apk add --no-cache ca-certificates curl

# Install kubectl for Kubernetes operations
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin/

WORKDIR /app

COPY --from=builder /build/prysm-backend /app/

EXPOSE 8080

CMD ["/app/prysm-backend"]