package repository

import (
	"context"
	"errors"
	"time"

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

func (repo *UserRepository) StoreVerificationToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	query := `
		INSERT INTO auth.email_verification_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`
	_, err := repo.db.Exec(ctx, query, userID, tokenHash, expiresAt)
	return err
}

func (repo *UserRepository) VerifyEmail(ctx context.Context, tokenHash string) error {
	query := `
		UPDATE auth.users
		SET email_verified = true
		WHERE id = (
			SELECT user_id FROM auth.email_verification_tokens
			WHERE token_hash = $1
			AND expires_at > now()
		)
	`

	result, err := repo.db.Exec(ctx, query, tokenHash)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return errors.New("invalid or expired verification token")
	}

	// delete the token so it can't be reused
	_, err = repo.db.Exec(ctx, `
		DELETE FROM auth.email_verification_tokens
		WHERE token_hash = $1
	`, tokenHash)

	return err
}

func (repo *UserRepository) StorePasswordResetToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	query := `
		INSERT INTO auth.password_reset_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`
	_, err := repo.db.Exec(ctx, query, userID, tokenHash, expiresAt)
	return err
}

func (repo *UserRepository) GetUserByPasswordResetToken(ctx context.Context, tokenHash string) (*model.User, error) {
	query := `
		SELECT u.id, u.email, u.password_hash, u.email_verified, u.status, u.created_at, u.updated_at
		FROM auth.users u
		JOIN auth.password_reset_tokens prt ON prt.user_id = u.id
		WHERE prt.token_hash = $1
		AND prt.expires_at > now()
	`

	var u model.User
	err := repo.db.QueryRow(ctx, query, tokenHash).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.EmailVerified, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}

	return &u, nil
}

func (repo *UserRepository) ResetPassword(ctx context.Context, userID, passwordHash, tokenHash string) error {
	query := ` UPDATE auth.users SET password_hash = $1 WHERE id = $2`
	_, err := repo.db.Exec(ctx, query, passwordHash, userID)
	if err != nil {
		return err
	}

	_, err = repo.db.Exec(ctx, `
		DELETE FROM auth.password_reset_tokens WHERE token_hash = $1
	`, tokenHash)

	return err
}
