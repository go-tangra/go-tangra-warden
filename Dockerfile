##################################
# Stage 0: Build frontend module
##################################

FROM node:20-alpine AS frontend-builder

RUN npm install -g pnpm@9

WORKDIR /frontend
COPY go-tangra-warden/frontend/package.json go-tangra-warden/frontend/pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile || pnpm install
COPY go-tangra-warden/frontend/ .
RUN pnpm build

##################################
# Stage 1: Build Go executable
##################################

FROM golang:1.23-alpine AS builder

ARG APP_VERSION=1.0.0

# Enable toolchain auto-download for newer Go versions
ENV GOTOOLCHAIN=auto

# Install build dependencies
RUN apk add --no-cache git make curl

# Install buf for proto descriptor generation
RUN curl -sSL "https://github.com/bufbuild/buf/releases/latest/download/buf-$(uname -s)-$(uname -m)" -o /usr/local/bin/buf && \
    chmod +x /usr/local/bin/buf

# Set working directory
WORKDIR /src

# Copy go mod files first for better caching
COPY go-tangra-warden/go.mod go-tangra-warden/go.sum ./

# Copy go-tangra-common (local dependency)
COPY go-tangra-common/ /go-tangra-common/
RUN go mod edit -replace github.com/go-tangra/go-tangra-common=/go-tangra-common

RUN go mod download

# Copy the entire source code
COPY go-tangra-warden/ .

# Regenerate proto descriptor (ensures embedded descriptor.bin is always up to date)
RUN buf build -o cmd/server/assets/descriptor.bin

# Build the server
RUN CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    go build -ldflags "-X main.version=${APP_VERSION} -s -w" \
    -o /src/bin/warden-server \
    ./cmd/server

##################################
# Stage 2: Create runtime image
##################################

FROM alpine:3.20

ARG APP_VERSION=1.0.0

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Set timezone
ENV TZ=UTC

# Set working directory
WORKDIR /app

# Copy executable from builder
COPY --from=builder /src/bin/warden-server /app/bin/warden-server

# Copy configuration files
COPY --from=builder /src/configs/ /app/configs/

# Copy frontend assets from frontend builder
COPY --from=frontend-builder /frontend/dist /app/frontend-dist

# Create non-root user
RUN addgroup -g 1000 warden && \
    adduser -D -u 1000 -G warden warden && \
    chown -R warden:warden /app

# Switch to non-root user
USER warden:warden

# Expose gRPC and HTTP ports
EXPOSE 9300 9301

# Set default command
CMD ["/app/bin/warden-server", "-c", "/app/configs"]

# Labels
LABEL org.opencontainers.image.title="Warden Service" \
      org.opencontainers.image.description="Secret Management Service with HashiCorp Vault" \
      org.opencontainers.image.version="${APP_VERSION}"
