# Auth Service — consultprompts.com

Identity & User Management microservice. Part of a 5-service architecture
(Auth, Agency & Web Development, Digital Products, Academy/LMS, Order & Payment)
sitting behind a single Go API Gateway, backed by PostgreSQL.

This service owns user identity only: registration, authentication, JWT issuance,
refresh tokens, and role management. It does not own profile data specific to
other domains — other services reference `user_id` as a foreign key into their
own schemas.

## Tech stack

- Go + Gin (HTTP routing)
- PostgreSQL via `pgx`/`pgxpool` (own `auth` schema)
- `golang-jwt/jwt/v5` — RS256-signed access tokens
- `bcrypt` — password hashing
- `air` — live reload during development
- `golang-migrate` SQL migrations (`/migrations`)

## Architecture

```
HTTP request → Handler → Service → Repository → Postgres
```

- **Handler** (`internal/handler`) — HTTP layer only. Parses/validates JSON,
  calls the service, translates results into status codes + JSON responses.
- **Service** (`internal/service`) — business logic (password hashing, JWT
  issuance, validation rules). No knowledge of HTTP.
- **Repository** (`internal/repository`) — SQL only. No business logic.

JWTs are signed with **RS256** (asymmetric), not HS256. Only this service holds
the private key (`jwt_private.pem`). The API Gateway and other services will
verify tokens using only the public key, fetched from this service's JWKS
endpoint — so a compromise of any other service can never be used to forge
tokens.

## Project structure

```
auth-service/
  main.go                  # entry point, dependency wiring
  internal/
    handler/                # HTTP handlers (Gin)
    service/                 # business logic
    repository/               # Postgres queries (pgx)
    model/                     # structs mirroring DB tables
  pkg/
    jwt/                       # RSA key loading, token issue/verify, hashing
  migrations/
    0001_init.up.sql / .down.sql
  .env                      # local secrets (gitignored)
  jwt_private.pem / jwt_public.pem   # RSA keypair (gitignored)
```

## Setup

1. Install Go, Postgres, and `air` (`go install github.com/air-verse/air@latest`)
2. Create a Postgres database (e.g. `consultprompts`) and run the migration in
   `migrations/0001_init.up.sql` against it
3. Generate an RSA keypair for JWT signing:
   ```
   openssl genrsa -out jwt_private.pem 2048
   openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem
   ```
4. Create a `.env` file:
   ```
   DB_HOST=localhost
   DB_PORT=5432
   DB_USER=postgres
   DB_PASSWORD=yourpassword
   DB_NAME=consultprompts
   DB_SSLMODE=disable
   PORT=8080
   ```
5. Run with live reload: `air`

## Endpoints (current)

| Method | Path            | Description                                  |
|--------|-----------------|-----------------------------------------------|
| GET    | /healthz        | Health check                                  |
| POST   | /auth/register  | Create a user, assign default `student` role  |
| POST   | /auth/login     | Verify credentials, issue access + refresh token |
| POST   | /auth/refresh   | Exchange a valid refresh token for a new access token |
| POST   | /auth/logout    | Revoke a specific refresh token               |

## Data model (`auth` schema)

- `users` — id, email, password_hash (nullable for OAuth-only), email_verified, status
- `oauth_identities` — links a user to a provider (google/github) account
- `roles` — student, b2b_client, admin, instructor (seeded)
- `user_roles` — many-to-many between users and roles
- `refresh_tokens` — hashed token storage, expiry, revocation timestamp

## TODO — remaining work

### Core auth features
- [ ] Add/remove roles for a user (admin operation)
- [ ] `GET /auth/me` + JWT auth middleware (verify access token, expose user to handlers)
- [ ] Email verification flow (token generation + confirmation endpoint)
- [ ] Password reset flow (request + reset endpoints)
- [ ] Refresh token rotation + reuse detection (theft response: revoke entire token family)
- [ ] JWKS endpoint (`/.well-known/jwks.json`) — **blocks the API Gateway project**
- [ ] Single active session enforcement — revoke all existing refresh tokens on new login
- [ ] Login notification emails (requires picking an email provider + async sending)
- [ ] OAuth login (Google, GitHub) — exchange provider code, link/create `oauth_identities`

### Validation & robustness
- [ ] Clean "email already registered" error instead of raw Postgres constraint error
- [ ] Password complexity rules (beyond current minimum length)
- [ ] Standardize error response shape across all endpoints
- [ ] Rate limiting on `/auth/login` (brute-force protection)

### Operational
- [ ] Wire up `golang-migrate` CLI instead of manually running SQL in pgAdmin
- [ ] Real secrets management for production (private key should not be a plain file in prod)
- [ ] Structured logging (login attempts, failures, audit trail)
- [ ] `/healthz` should verify actual DB connectivity, not just process liveness
- [ ] Dockerfile for this service
- [ ] Automated tests (unit tests for service layer, integration tests for handlers)

### Beyond this service
- [ ] Build the API Gateway (separate Go project) — routing, rate limiting, JWT
      verification using this service's public key, forwarding trusted headers
      (`X-User-ID`, `X-User-Roles`) downstream
- [ ] Agency & Web Development service
- [ ] Digital Products (Ebooks & Webinars) service
- [ ] Academy (LMS) service
- [ ] Order & Payment service
