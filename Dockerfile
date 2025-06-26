# Build stage
FROM golang:1.24.4-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata nodejs npm

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download Go dependencies
RUN go mod download

# Install templ CLI
RUN go install github.com/a-h/templ/cmd/templ@latest

# Copy source code
COPY . .

# Generate templ files
RUN templ generate

# Build Tailwind CSS
WORKDIR /app/ui
RUN npm install
RUN npx tailwindcss -i input.css -o static/output.css --minify

# Build the application
WORKDIR /app
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o main .

# Production stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata sqlite

# Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/main .

# Copy static assets (including built CSS)
COPY --from=builder /app/ui/static ./ui/static

# Copy database migrations
COPY --from=builder /app/migrations ./migrations

# Create data directory for SQLite database
RUN mkdir -p /app/data && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Railway uses PORT environment variable
ENV PORT=8080

# Expose port (Railway will override this)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:$PORT/health || exit 1

# Run the application
CMD ["./main"] 