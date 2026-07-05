# Stage 1 — builder
FROM golang:1.26.4-alpine AS builder

WORKDIR /app

COPY auth-service/go.mod auth-service/go.sum ./
RUN go mod download

COPY auth-service/ .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -o auth-service .

# Stage 2 — final image
FROM gcr.io/distroless/static-debian12

WORKDIR /

COPY --from=builder /app/auth-service .

# Copy JWT keys
# TODO: mount these as Docker secrets in production instead of baking into image
COPY --from=builder /app/jwt_private.pem .
COPY --from=builder /app/jwt_public.pem .
COPY --from=builder /app/migrations/ migrations/

EXPOSE 8081

ENTRYPOINT ["/auth-service"]
