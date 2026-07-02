package service

import (
	"context"
	"crypto/rsa"
	"errors"
	"log/slog"
	"time"

	"github.com/consultprompts/auth-service/internal/model"
	"github.com/consultprompts/auth-service/pkg/jwt"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"
)

var ErrInvalidCredentials = errors.New("Invalid email or password")
var ErrInvalidRefreshToken = errors.New("Invalid or expired refresh token")
var ErrUserNotFound = errors.New("User not found")
var ErrEmailNotVerified = errors.New("Email not verified")
var ErrEmailAlreadyVerified = errors.New("Email is already verified")
var ErrEmailAlreadyRegistered = errors.New("email already registered")

type AuthService struct {
	userRepo    UserRepository
	tokenRepo   TokenRepository
	roleRepo    RoleRepository
	emailClient EmailClient
	privateKey  *rsa.PrivateKey
}

func NewAuthService(
	userRepo UserRepository,
	tokenRepo TokenRepository,
	roleRepo RoleRepository,
	emailClient EmailClient,
	privateKey *rsa.PrivateKey,
) *AuthService {
	return &AuthService{
		userRepo:    userRepo,
		tokenRepo:   tokenRepo,
		roleRepo:    roleRepo,
		emailClient: emailClient,
		privateKey:  privateKey,
	}
}

func (service *AuthService) Register(ctx context.Context, email, password string) (*model.User, error) {
	if len(password) < 8 {
		return nil, errors.New("password must be at least 8 characters")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user, err := service.userRepo.CreateUser(ctx, email, string(hash))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrEmailAlreadyRegistered
		}
		return nil, err
	}

	if err := service.roleRepo.AssignRoleByName(ctx, user.ID, "student"); err != nil {
		return nil, err
	}

	// generate verification token
	verificationToken, err := jwt.GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

	tokenHash := jwt.HashToken(verificationToken)
	expiresAt := time.Now().Add(24 * time.Hour)

	if err := service.userRepo.StoreVerificationToken(ctx, user.ID, tokenHash, expiresAt); err != nil {
		return nil, err
	}

	// send verification email asynchronously
	go func() {
		if err := service.emailClient.SendVerificationEmail(user.Email, verificationToken); err != nil {
			slog.Error("failed to send verification email", "email", user.Email, "error", err)
		}
	}()

	return user, nil
}

func (service *AuthService) Login(ctx context.Context, email, password string) (accessToken string, refreshToken string, err error) {
	user, err := service.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return "", "", ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", "", ErrInvalidCredentials
	}

	if !user.EmailVerified {
		return "", "", ErrEmailNotVerified
	}

	var userRoles []string
	userRoles, err = service.roleRepo.GetRoleNamesByUserID(ctx, user.ID)
	if err != nil {
		return "", "", err
	}

	if err := service.tokenRepo.RevokeAllUserTokens(ctx, user.ID); err != nil {
		return "", "", err
	}

	accessToken, err = jwt.IssueAccessToken(service.privateKey, user.ID, userRoles, 15*time.Minute)
	if err != nil {
		return "", "", err
	}

	refreshToken, err = jwt.GenerateRefreshToken()
	if err != nil {
		return "", "", err
	}

	tokenHash := jwt.HashToken(refreshToken)
	expiresAt := time.Now().Add(30 * 24 * time.Hour)

	if err := service.tokenRepo.StoreRefreshToken(ctx, user.ID, tokenHash, expiresAt); err != nil {
		return "", "", err
	}

	// BECAUSE OF EMAIL API LIMITS IT IS DISABLE FOR TESTING

	// go func() {
	// 	if err := service.emailClient.SendLoginNotificationEmail(user.Email); err != nil {
	// 		slog.Error("failed to send login notification", "email", user.Email, "error", err)
	// 	}
	// }()

	return accessToken, refreshToken, nil
}

func (service *AuthService) RefreshAccessToken(ctx context.Context, refreshToken string) (string, string, error) {
	tokenHash := jwt.HashToken(refreshToken)

	stored, err := service.tokenRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return "", "", ErrInvalidRefreshToken
	}

	// reuse detection — token was already rotated, possible theft
	if stored.RevokedAt != nil {
		if err := service.tokenRepo.RevokeAllUserTokens(ctx, stored.UserID); err != nil {
			return "", "", err
		}
		return "", "", ErrInvalidRefreshToken
	}

	if time.Now().After(stored.ExpiresAt) {
		return "", "", ErrInvalidRefreshToken
	}

	// revoke the old token
	if err := service.tokenRepo.RevokeToken(ctx, tokenHash); err != nil {
		return "", "", err
	}

	// get all the roles for that user
	roles, err := service.roleRepo.GetRoleNamesByUserID(ctx, stored.UserID)
	if err != nil {
		return "", "", err
	}

	// issue new access token
	accessToken, err := jwt.IssueAccessToken(service.privateKey, stored.UserID, roles, 15*time.Minute)
	if err != nil {
		return "", "", err
	}

	// issue new refresh token
	newRefreshToken, err := jwt.GenerateRefreshToken()
	if err != nil {
		return "", "", err
	}

	// store new refresh token
	tokenHash = jwt.HashToken(newRefreshToken)
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	if err := service.tokenRepo.StoreRefreshToken(ctx, stored.UserID, tokenHash, expiresAt); err != nil {
		return "", "", err
	}

	return accessToken, newRefreshToken, nil
}

func (service *AuthService) Logout(ctx context.Context, refreshToken string) error {
	tokenHash := jwt.HashToken(refreshToken)
	return service.tokenRepo.RevokeToken(ctx, tokenHash)
}

func (service *AuthService) AssignRole(ctx context.Context, userID, roleName string) error {
	return service.roleRepo.AssignRoleByName(ctx, userID, roleName)
}

func (service *AuthService) RemoveRole(ctx context.Context, userID, roleName string) error {
	return service.roleRepo.RemoveRoleByName(ctx, userID, roleName)
}

func (service *AuthService) VerifyEmail(ctx context.Context, token string) error {
	tokenHash := jwt.HashToken(token)
	return service.userRepo.VerifyEmail(ctx, tokenHash)
}

func (service *AuthService) RequestPasswordReset(ctx context.Context, emailAddr string) error {
	user, err := service.userRepo.GetUserByEmail(ctx, emailAddr)
	if err != nil {
		// deliberately return nil even if user not found
		// so we don't leak which emails are registered
		return nil
	}

	resetToken, err := jwt.GenerateRefreshToken()
	if err != nil {
		return err
	}

	tokenHash := jwt.HashToken(resetToken)
	expiresAt := time.Now().Add(1 * time.Hour)

	if err := service.userRepo.StorePasswordResetToken(ctx, user.ID, tokenHash, expiresAt); err != nil {
		return err
	}

	go func() {
		if err := service.emailClient.SendPasswordResetEmail(user.Email, resetToken); err != nil {
			slog.Error("failed to send password reset email", "email", user.Email, "error", err)
		}
	}()

	return nil
}

func (service *AuthService) ResetPassword(ctx context.Context, token, newPassword string) error {
	if len(newPassword) < 8 {
		return errors.New("Password must be at least 8 characters")
	}

	tokenHash := jwt.HashToken(token)

	user, err := service.userRepo.GetUserByPasswordResetToken(ctx, tokenHash)
	if err != nil {
		return errors.New("Invalid or expired reset token")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// revoke all sessions — force re-login after password reset
	if err := service.tokenRepo.RevokeAllUserTokens(ctx, user.ID); err != nil {
		return err
	}

	return service.userRepo.ResetPassword(ctx, user.ID, string(hash), tokenHash)
}

func (service *AuthService) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	return service.userRepo.GetUserByID(ctx, id)
}

func (service *AuthService) ResendVerificationEmail(ctx context.Context, emailAddr string) error {
	user, err := service.userRepo.GetUserByEmail(ctx, emailAddr)
	if err != nil {
		// don't leak whether email exists
		return nil
	}

	if user.EmailVerified {
		return ErrEmailAlreadyVerified
	}

	token, err := jwt.GenerateRefreshToken()
	if err != nil {
		return err
	}

	tokenHash := jwt.HashToken(token)
	expiresAt := time.Now().Add(24 * time.Hour)

	if err := service.userRepo.ReplaceVerificationToken(ctx, user.ID, tokenHash, expiresAt); err != nil {
		return err
	}

	go func() {
		if err := service.emailClient.SendVerificationEmail(user.Email, token); err != nil {
			slog.Error("Failed to resend verification email", "email", user.Email, "error", err)
		}
	}()

	return nil
}
