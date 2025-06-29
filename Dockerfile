# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod ./
COPY watch/go.mod ./watch/

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build both applications
RUN go build -o tosot-ac-control main.go
RUN cd watch && go build -o ../ac-watch main.go

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 -S appuser && \
    adduser -u 1000 -S appuser -G appuser

# Set working directory
WORKDIR /app

# Copy binaries from builder
COPY --from=builder /app/tosot-ac-control /app/
COPY --from=builder /app/ac-watch /app/

# Create directories for state files
RUN mkdir -p /app/data && chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Set volume for persistent data
VOLUME ["/app/data"]

# Default to running the watch program
CMD ["./ac-watch"]