# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache gcc musl-dev sqlite-dev

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY main.go .

# Build application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o auth-app .

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates sqlite-libs

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/auth-app .

# Copy static files
COPY static ./static

# Create data directory
RUN mkdir -p /data

# Set environment variables
ENV PORT=8080
ENV DATABASE_PATH=/data/auth.db
ENV APP_NAME="Auth App"
ENV APP_ICON="🔐"

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
	CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

CMD ["./auth-app"]
