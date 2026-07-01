-- Auth service initial schema
-- Run with golang-migrate or goose against the auth service's Postgres database/schema

CREATE SCHEMA IF NOT EXISTS auth;

CREATE EXTENSION IF NOT EXISTS pgcrypto; -- for gen_random_uuid()

CREATE TABLE auth.users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NULL,           -- NULL allowed: OAuth-only users have no password
    email_verified  BOOLEAN NOT NULL DEFAULT false,
    status          TEXT NOT NULL DEFAULT 'active', -- active, suspended, deleted
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth.oauth_identities (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    provider          TEXT NOT NULL,        -- 'google', 'github', etc.
    provider_user_id  TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, provider_user_id)
);

CREATE INDEX idx_oauth_identities_user_id ON auth.oauth_identities(user_id);

CREATE TABLE auth.roles (
    id    SERIAL PRIMARY KEY,
    name  TEXT NOT NULL UNIQUE  -- student, b2b_client, admin, instructor
);

CREATE TABLE auth.user_roles (
    user_id  UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    role_id  INT NOT NULL REFERENCES auth.roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE auth.refresh_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL UNIQUE,
    device_info  TEXT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_refresh_tokens_user_id ON auth.refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON auth.refresh_tokens(expires_at);

-- Seed default roles
INSERT INTO auth.roles (name) VALUES
    ('student'),
    ('b2b_client'),
    ('admin'),
    ('instructor')
ON CONFLICT (name) DO NOTHING;
