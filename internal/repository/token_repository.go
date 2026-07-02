package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type TokenRepository struct {
	db *pgxpool.Pool
}

func NewTokenRepository(db *pgxpool.Pool) *TokenRepository {
	return &TokenRepository{db: db}
}

func (repo *TokenRepository) StoreRefreshToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	query := `
		INSERT INTO auth.refresh_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`

	_, err := repo.db.Exec(ctx, query, userID, tokenHash, expiresAt)
	return err
}

type RefreshToken struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	RevokedAt *time.Time
}

func (repo *TokenRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	query := `
		SELECT id, user_id, token_hash, expires_at, revoked_at
		FROM auth.refresh_tokens
		WHERE token_hash = $1
	`

	var t RefreshToken
	err := repo.db.QueryRow(ctx, query, tokenHash).Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.RevokedAt)
	if err != nil {
		return nil, err
	}

	return &t, nil
}

func (repo *TokenRepository) RevokeToken(ctx context.Context, tokenHash string) error {
	query := `
		UPDATE auth.refresh_tokens
		SET revoked_at = now()
		WHERE token_hash = $1
	`

	_, err := repo.db.Exec(ctx, query, tokenHash)
	return err
}

func (repo *TokenRepository) RevokeAllUserTokens(ctx context.Context, userID string) error {
	query := `
		UPDATE auth.refresh_tokens
		SET revoked_at = now()
		WHERE user_id = $1 AND revoked_at IS NULL
	`
	_, err := repo.db.Exec(ctx, query, userID)
	return err
}
