# Auth Service — consultprompts.com

Identity & User Management microservice. Part of a 5-service architecture
(Auth, Agency & Web Development, Digital Products, Academy/LMS, Order & Payment)
sitting behind a single Go API Gateway, backed by PostgreSQL.

This service owns user identity only: registration, authentication, JWT issuance,
refresh tokens, role management, email verification, and password reset. It does
not own profile data specific to other domains — other services reference `user_id`
as a foreign key into their own schemas.

---

## Tech Stack

- Go + Gin (HTTP routing)
- PostgreSQL via `pgx`/`pgxpool` (own `auth` schema)
- `golang-jwt/jwt/v5` — RS256-signed access tokens
- `bcrypt` — password hashing
- `golang-migrate` — automated database migrations
- `resend-go` — transactional email (verification, password reset, login notifications)
- `air` — live reload during development
- Docker + Docker Compose — containerized runtime

---

## Security Features

- RS256 asymmetric JWT signing — only auth-service holds the private key; the API Gateway and other services verify using the public key via `/.well-known/jwks.json`
- bcrypt password hashing — plaintext passwords never stored
- Refresh token rotation with reuse detection — if a rotated token is reused, all sessions for that user are immediately revoked (theft response)
- Single active session enforcement — new login revokes all previous refresh tokens
- Progressive login rate limiting — 5 failed attempts → 1 min lockout, 7 → 3 min, 10 → 10 min
- Email verification required before login
- Login notification emails on every successful login
- Short-lived access tokens (15 min) + long-lived refresh tokens (30 days)
- Soft-delete approach for tokens (`revoked_at` timestamp, never hard DELETE)
- Role-based access control (student, b2b_client, admin, instructor)

---

## Architecture

```
HTTP request → Handler → Service → Repository → Postgres
```

- **Handler** (`internal/handler`) — HTTP layer only. Parses/validates JSON, calls the service, translates results into status codes + JSON responses.
- **Service** (`internal/service`) — business logic (password hashing, JWT issuance, validation rules). No knowledge of HTTP or SQL.
- **Repository** (`internal/repository`) — SQL only. No business logic.

JWTs are signed with **RS256** (asymmetric). Only this service holds the private key (`jwt_private.pem`). The API Gateway and other services verify tokens using only the public key, fetched from `/.well-known/jwks.json` — so a compromise of any other service cannot be used to forge tokens.

---

## Project Structure

```
auth-service/
  main.go                        # entry point, dependency wiring
  database/
    db.go                        # Postgres connection pool + golang-migrate runner
  internal/
    handler/                     # HTTP handlers (Gin) + response helpers
    service/                     # business logic + interfaces
    repository/                  # Postgres queries (pgx)
    model/                       # structs mirroring DB tables
    middleware/                  # JWT auth, role guard, rate limiting, logging
    email/                       # Resend email client
  pkg/
    jwt/                         # RSA key loading, token issue/verify, hashing
  migrations/
    0001_init.up.sql / .down.sql
    0002_email_verification.up.sql / .down.sql
    0003_password_reset.up.sql / .down.sql
  .env                           # local secrets (gitignored)
  .env.example                   # template for required environment variables
  jwt_private.pem                # RSA private key (gitignored)
  jwt_public.pem                 # RSA public key (gitignored)
  Dockerfile
  docker-compose.yml
```

---

## Data Model (`auth` schema)

| Table | Description |
|-------|-------------|
| `users` | id, email, password_hash (nullable for OAuth), email_verified, status |
| `oauth_identities` | links a user to a provider (google/github) account |
| `roles` | student, b2b_client, admin, instructor (seeded) |
| `user_roles` | many-to-many between users and roles |
| `refresh_tokens` | hashed token storage, expiry, revocation timestamp |
| `email_verification_tokens` | hashed token, expiry, deleted on use |
| `password_reset_tokens` | hashed token, expiry, deleted on use |

---

## Endpoints

| Method | Path | Auth Required | Description |
|--------|------|---------------|-------------|
| GET | /healthz | No | Health check with real DB connectivity verification |
| POST | /auth/register | No | Register user, assign student role, send verification email |
| POST | /auth/login | No | Login, issue JWT pair, send login notification email |
| POST | /auth/refresh | No | Rotate refresh token, issue new JWT pair |
| POST | /auth/logout | No | Revoke current refresh token |
| POST | /auth/verify-email | No | Verify email with token from email link |
| POST | /auth/verify-email/resend | No | Resend verification email |
| POST | /auth/password/reset-request | No | Request password reset email |
| POST | /auth/password/reset | No | Reset password with token |
| GET | /auth/me | Yes | Get current user info (id, roles) |
| POST | /auth/roles/assign | Yes (admin) | Assign a role to a user |
| POST | /auth/roles/remove | Yes (admin) | Remove a role from a user |
| GET | /auth/users/:id | Yes (admin) | Get user details by ID |
| GET | /.well-known/jwks.json | No | RS256 public key in JWKS format for JWT verification |

### Response Shape

Every endpoint returns a consistent JSON structure:

```json
// Success
{
  "success": true,
  "data": { ... }
}

// Error
{
  "success": false,
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "invalid email or password"
  }
}
```

---

## Setup (Local Development)

**Prerequisites**: Go 1.26+, PostgreSQL, `air`

**1. Install air for live reload:**
```bash
go install github.com/air-verse/air@latest
```

**2. Generate RSA keypair for JWT signing:**
```bash
openssl genrsa -out jwt_private.pem 2048
openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem
```

**3. Create `.env` from the template:**
```bash
cp .env.example .env
# fill in your actual values
```

**4. Create a Postgres database** (`consultprompts`) and update `.env` with your credentials.

**5. Run with live reload:**
```bash
air
```

Migrations run automatically on startup. No manual SQL needed.

---

## Running with Docker

**Start everything (auth-service + Postgres):**
```bash
docker compose up --build
```

**Stop (keeps database data):**
```bash
docker compose down
```

**Full reset (wipes database volume):**
```bash
docker compose down -v
```

Migrations run automatically on startup via golang-migrate.
Postgres data persists in a named Docker volume (`postgres_data`).

> **Note**: when switching between local (`air`) and Docker, update `DB_HOST` in `.env`:
> - Local: `DB_HOST=localhost`
> - Docker: `DB_HOST=postgres`

---

## Tests

Run service layer tests:
```bash
go test ./internal/service/... -v
```

18 tests covering Register, Login, Refresh, Logout, VerifyEmail, RequestPasswordReset, ResetPassword — all passing.

Service layer uses interfaces for all dependencies (repositories, email client), allowing full mock injection in tests without a real database or email provider.

---

## TODO

### v1.1
- [ ] OAuth login (Google)

### v2.0
- [ ] Redis token blocklist (instant access token revocation — currently 15 min window on logout)
- [ ] Redis-backed rate limiting (multi-instance support)

### Beyond auth-service
- [ ] API Gateway (separate Go project — single entry point, JWT verification via `/.well-known/jwks.json`, routing to all microservices)
- [ ] Agency & Web Development service
- [ ] Digital Products (Ebooks & Webinars) service
- [ ] Academy (LMS) service
- [ ] Order & Payment service
