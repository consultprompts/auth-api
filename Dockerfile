# Stage 1 — builder
FROM golang:1.26.4-alpine AS builder

WORKDIR /app

# Copy dependency files first (cached as separate layer)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -o auth-service .

# Stage 2 — final image
FROM gcr.io/distroless/static-debian12

WORKDIR /

# Copy binary from builder
COPY --from=builder /app/auth-service .

# Copy JWT keys
# TODO: mount these as Docker secrets in production instead of baking into image
COPY jwt_private.pem .
COPY jwt_public.pem .
COPY migrations/ migrations/

EXPOSE 8081

ENTRYPOINT ["/auth-service"]
