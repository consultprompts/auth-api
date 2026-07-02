package handler

import (
	"crypto/rsa"
	"net/http"

	"github.com/consultprompts/auth-service/internal/middleware"
	"github.com/consultprompts/auth-service/internal/response"
	"github.com/consultprompts/auth-service/internal/service"
	jwtpkg "github.com/consultprompts/auth-service/pkg/jwt"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AuthHandler struct {
	authService *service.AuthService
	publicKey   *rsa.PublicKey
	pool        *pgxpool.Pool
}

func NewAuthHandler(authService *service.AuthService, publicKey *rsa.PublicKey, pool *pgxpool.Pool) *AuthHandler {
	return &AuthHandler{authService: authService, publicKey: publicKey, pool: pool}
}

type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type UserResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func (handler *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest

	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.RespondError(c, http.StatusBadRequest, response.ErrCodeInvalidInput, err.Error())
		return
	}

	user, err := handler.authService.Register(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		response.RespondError(c, http.StatusInternalServerError, response.ErrCodeInternalError, err.Error())
		return
	}

	c.JSON(http.StatusCreated, UserResponse{
		ID:    user.ID,
		Email: user.Email,
	})
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (handler *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.RespondError(c, http.StatusBadRequest, response.ErrCodeInvalidInput, err.Error())
		return
	}

	accessToken, refreshToken, err := handler.authService.Login(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		response.RespondError(c, http.StatusUnauthorized, response.ErrCodeInvalidCredentials, err.Error())
		return
	}

	c.JSON(http.StatusOK, LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (handler *AuthHandler) Refresh(c *gin.Context) {
	var req RefreshRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.RespondError(c, http.StatusBadRequest, response.ErrCodeInvalidInput, err.Error())
		return
	}

	accessToken, refreshToken, err := handler.authService.RefreshAccessToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		response.RespondError(c, http.StatusUnauthorized, response.ErrCodeInvalidToken, err.Error())
		return
	}

	c.JSON(http.StatusOK, RefreshResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func (handler *AuthHandler) Logout(c *gin.Context) {
	var req LogoutRequest

	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.RespondError(c, http.StatusBadRequest, response.ErrCodeInvalidInput, err.Error())
		return
	}

	err = handler.authService.Logout(c.Request.Context(), req.RefreshToken)
	if err != nil {
		response.RespondError(c, http.StatusInternalServerError, response.ErrCodeInternalError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

func (handler *AuthHandler) JWKS(c *gin.Context) {
	jwks := jwtpkg.PublicKeyToJWKSet(handler.publicKey)
	c.JSON(http.StatusOK, jwks)
}

func (handler *AuthHandler) Me(c *gin.Context) {
	userID, exists := c.Get(middleware.ContextUserID)
	if !exists {
		response.RespondError(c, http.StatusUnauthorized, response.ErrCodeUnauthorized, "unauthorized")
		return
	}

	roles, _ := c.Get(middleware.ContextUserRoles)

	c.JSON(http.StatusOK, gin.H{
		"id":    userID,
		"roles": roles,
	})
}

type RoleRequest struct {
	UserID   string `json:"user_id" binding:"required"`
	RoleName string `json:"role_name" binding:"required"`
}

func (handler *AuthHandler) AssignRole(c *gin.Context) {
	var req RoleRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.RespondError(c, http.StatusBadRequest, response.ErrCodeInvalidInput, err.Error())
		return
	}

	if err := handler.authService.AssignRole(c.Request.Context(), req.UserID, req.RoleName); err != nil {
		response.RespondError(c, http.StatusInternalServerError, response.ErrCodeInternalError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "role assigned successfully"})
}

func (handler *AuthHandler) RemoveRole(c *gin.Context) {
	var req RoleRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.RespondError(c, http.StatusBadRequest, response.ErrCodeInvalidInput, err.Error())
		return
	}

	if err := handler.authService.RemoveRole(c.Request.Context(), req.UserID, req.RoleName); err != nil {
		response.RespondError(c, http.StatusInternalServerError, response.ErrCodeInternalError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "role removed successfully"})
}

type VerifyEmailRequest struct {
	Token string `json:"token" binding:"required"`
}

func (handler *AuthHandler) VerifyEmail(c *gin.Context) {
	var req VerifyEmailRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.RespondError(c, http.StatusBadRequest, response.ErrCodeInvalidInput, err.Error())
		return
	}

	if err := handler.authService.VerifyEmail(c.Request.Context(), req.Token); err != nil {
		response.RespondError(c, http.StatusBadRequest, response.ErrCodeInvalidToken, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "email verified successfully"})
}

type PasswordResetRequestRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type PasswordResetRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

func (handler *AuthHandler) RequestPasswordReset(c *gin.Context) {
	var req PasswordResetRequestRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.RespondError(c, http.StatusBadRequest, response.ErrCodeInvalidInput, err.Error())
		return
	}

	if err := handler.authService.RequestPasswordReset(c.Request.Context(), req.Email); err != nil {
		response.RespondError(c, http.StatusInternalServerError, response.ErrCodeInternalError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "If that email exists, a reset link has been sent"})
}

func (handler *AuthHandler) ResetPassword(c *gin.Context) {
	var req PasswordResetRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.RespondError(c, http.StatusBadRequest, response.ErrCodeInvalidInput, err.Error())
		return
	}

	if err := handler.authService.ResetPassword(c.Request.Context(), req.Token, req.NewPassword); err != nil {
		response.RespondError(c, http.StatusBadRequest, response.ErrCodeInvalidToken, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

func (handler *AuthHandler) Healthz(c *gin.Context) {
	if err := handler.pool.Ping(c.Request.Context()); err != nil {
		RespondError(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "database connection failed")
		return
	}
	RespondOK(c, gin.H{"status": "ok"})
}
