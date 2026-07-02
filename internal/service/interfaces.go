package service

import (
	"context"
	"time"

	"github.com/consultprompts/auth-service/internal/model"
	"github.com/consultprompts/auth-service/internal/repository"
)

type UserRepository interface {
	CreateUser(ctx context.Context, email, passwordHash string) (*model.User, error)
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	GetUserByID(ctx context.Context, id string) (*model.User, error)
	StoreVerificationToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error
	VerifyEmail(ctx context.Context, tokenHash string) error
	ReplaceVerificationToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error
	StorePasswordResetToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error
	GetUserByPasswordResetToken(ctx context.Context, tokenHash string) (*model.User, error)
	ResetPassword(ctx context.Context, userID, passwordHash, tokenHash string) error
}

type TokenRepository interface {
	StoreRefreshToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*repository.RefreshToken, error)
	RevokeToken(ctx context.Context, tokenHash string) error
	RevokeAllUserTokens(ctx context.Context, userID string) error
}

type RoleRepository interface {
	AssignRoleByName(ctx context.Context, userID, roleName string) error
	GetRoleNamesByUserID(ctx context.Context, userID string) ([]string, error)
	RemoveRoleByName(ctx context.Context, userID, roleName string) error
}

type EmailClient interface {
	SendVerificationEmail(to, token string) error
	SendPasswordResetEmail(to, token string) error
	SendLoginNotificationEmail(to string) error
}
