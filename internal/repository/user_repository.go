package repository

import (
	"context"

	"github.com/consultprompts/auth-service/internal/model"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepository struct {
	db *pgxpool.Pool
}

func NewUserRepository(db *pgxpool.Pool) *UserRepository {
	return &UserRepository{db: db}
}

func (repo *UserRepository) CreateUser(ctx context.Context, email, passwordHash string) (*model.User, error) {
	query := `
		INSERT INTO auth.users (email, password_hash)
		VALUES ($1, $2)
		RETURNING id, email, password_hash, email_verified, status, created_at, updated_at
	`

	var user model.User
	err := repo.db.QueryRow(ctx, query, email, passwordHash).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.EmailVerified, &user.Status, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (repo *UserRepository) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	query := `
		SELECT id, email, password_hash, email_verified, status, created_at, updated_at
		FROM auth.users
		WHERE email = $1
	`

	var user model.User
	err := repo.db.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.EmailVerified,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, err
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
