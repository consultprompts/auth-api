package handler

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"time"

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
		if errors.Is(err, service.ErrEmailAlreadyRegistered) {
			response.RespondError(c, http.StatusConflict, response.ErrCodeEmailExists, err.Error())
			return
		}
		response.RespondError(c, http.StatusInternalServerError, response.ErrCodeInternalError, "an internal error occurred")
		return
	}

	response.RespondCreated(c, UserResponse{
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
		if errors.Is(err, service.ErrEmailNotVerified) {
			response.RespondError(c, http.StatusForbidden, response.ErrCodeEmailNotVerified, err.Error())
			return
		}
		if errors.Is(err, service.ErrAccountNotActive) {
			response.RespondError(c, http.StatusForbidden, response.ErrCodeForbidden, err.Error())
			return
		}
		if errors.Is(err, service.ErrInvalidCredentials) {
			response.RespondError(c, http.StatusUnauthorized, response.ErrCodeInvalidCredentials, err.Error())
			return
		}
		response.RespondError(c, http.StatusInternalServerError, response.ErrCodeInternalError, "an internal error occurred")
		return
	}

	response.RespondOK(c, LoginResponse{
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
		if errors.Is(err, service.ErrInvalidRefreshToken) {
			response.RespondError(c, http.StatusUnauthorized, response.ErrCodeInvalidToken, err.Error())
			return
		}
		response.RespondError(c, http.StatusInternalServerError, response.ErrCodeInternalError, "an internal error occurred")
		return
	}

	response.RespondOK(c, RefreshResponse{
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
		response.RespondError(c, http.StatusInternalServerError, response.ErrCodeInternalError, "an internal error occurred")
		return
	}

	response.RespondOK(c, gin.H{"message": "Logout successful"})
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

	user, err := handler.authService.GetUserByID(c.Request.Context(), userID.(string))
	if err != nil {
		response.RespondError(c, http.StatusInternalServerError, response.ErrCodeInternalError, "an internal error occurred")
		return
	}

	response.RespondOK(c, gin.H{
		"id":             userID,
		"roles":          roles,
		"email":          user.Email,
		"email_verified": user.EmailVerified,
		"created_at":     user.CreatedAt,
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
		response.RespondError(c, http.StatusInternalServerError, response.ErrCodeInternalError, "an internal error occurred")
		return
	}

	response.RespondOK(c, gin.H{"message": "role assigned successfully"})
}

func (handler *AuthHandler) RemoveRole(c *gin.Context) {
	var req RoleRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.RespondError(c, http.StatusBadRequest, response.ErrCodeInvalidInput, err.Error())
		return
	}

	if err := handler.authService.RemoveRole(c.Request.Context(), req.UserID, req.RoleName); err != nil {
		response.RespondError(c, http.StatusInternalServerError, response.ErrCodeInternalError, "an internal error occurred")
		return
	}

	response.RespondOK(c, gin.H{"message": "role removed successfully"})
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

	response.RespondOK(c, gin.H{"message": "email verified successfully"})
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
		response.RespondError(c, http.StatusInternalServerError, response.ErrCodeInternalError, "an internal error occurred")
		return
	}

	response.RespondOK(c, gin.H{"message": "If that email exists, a reset link has been sent"})
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

	response.RespondOK(c, gin.H{"message": "Password reset successfully"})
}

func (handler *AuthHandler) Healthz(c *gin.Context) {
	if err := handler.pool.Ping(c.Request.Context()); err != nil {
		response.RespondError(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "database connection failed")
		return
	}
	response.RespondOK(c, gin.H{"status": "ok"})
}

type UserDetailResponse struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
}

func (h *AuthHandler) GetUser(c *gin.Context) {
	userID := c.Param("id")

	user, err := h.authService.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		response.RespondError(c, http.StatusNotFound, "USER_NOT_FOUND", "user not found")
		return
	}

	response.RespondOK(c, UserDetailResponse{
		ID:            user.ID,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Status:        user.Status,
		CreatedAt:     user.CreatedAt,
	})
}

type ResendVerificationRequest struct {
	Email string `json:"email" binding:"required,email"`
}

func (handler *AuthHandler) ResendVerification(c *gin.Context) {
	var req ResendVerificationRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.RespondError(c, http.StatusBadRequest, response.ErrCodeInvalidInput, err.Error())
		return
	}

	if err := handler.authService.ResendVerificationEmail(c.Request.Context(), req.Email); err != nil {
		// an already-verified email falls through to the generic response so the
		// endpoint doesn't reveal whether an account exists
		if !errors.Is(err, service.ErrEmailAlreadyVerified) {
			response.RespondError(c, http.StatusInternalServerError, response.ErrCodeInternalError, "an internal error occurred")
			return
		}
	}

	response.RespondOK(c, gin.H{"message": "if that email exists and is unverified, a new verification link has been sent"})
}
