package service

import (
	"context"
	"crypto/rsa"
	"errors"
	"time"

	"github.com/consultprompts/auth-service/internal/model"
	"github.com/consultprompts/auth-service/internal/repository"
	"github.com/consultprompts/auth-service/pkg/jwt"
	"golang.org/x/crypto/bcrypt"
)

var ErrInvalidCredentials = errors.New("Invalid email or password")
var ErrInvalidRefreshToken = errors.New("Invalid or expired refresh token")

type AuthService struct {
	userRepo   *repository.UserRepository
	tokenRepo  *repository.TokenRepository
	roleRepo   *repository.RoleRepository
	privateKey *rsa.PrivateKey
}

func NewAuthService(userRepo *repository.UserRepository, tokenRepo *repository.TokenRepository, roleRepo *repository.RoleRepository, privateKey *rsa.PrivateKey) *AuthService {
	return &AuthService{userRepo: userRepo, tokenRepo: tokenRepo, roleRepo: roleRepo, privateKey: privateKey}
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
		return nil, err
	}

	if err := service.roleRepo.AssignRoleByName(ctx, user.ID, "student"); err != nil {
		return nil, err
	}

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

	var userRoles []string
	userRoles, err = service.roleRepo.GetRoleNamesByUserID(ctx, user.ID)
	if err != nil {
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

	return accessToken, refreshToken, nil
}

func (service *AuthService) RefreshAccessToken(ctx context.Context, refreshToken string) (string, error) {
	tokenHash := jwt.HashToken(refreshToken)

	stored, err := service.tokenRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return "", ErrInvalidRefreshToken
	}

	if stored.RevokedAt != nil {
		return "", ErrInvalidRefreshToken
	}

	if time.Now().After(stored.ExpiresAt) {
		return "", ErrInvalidRefreshToken
	}

	accessToken, err := jwt.IssueAccessToken(service.privateKey, stored.UserID, []string{}, 15*time.Minute)
	if err != nil {
		return "", err
	}

	return accessToken, nil
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
