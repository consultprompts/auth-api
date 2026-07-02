package middleware

import (
	"crypto/rsa"
	"net/http"
	"strings"

	"github.com/consultprompts/auth-service/internal/response"
	jwtpkg "github.com/consultprompts/auth-service/pkg/jwt"
	"github.com/gin-gonic/gin"
)

const (
	ContextUserID    = "userID"
	ContextUserRoles = "userRoles"
)

func RequireAuth(publicKey *rsa.PublicKey) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			response.RespondError(c, http.StatusUnauthorized, response.ErrCodeUnauthorized, "missing or invalid authorization header")
			c.Abort()
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := jwtpkg.VerifyToken(tokenString, publicKey)
		if err != nil {
			response.RespondError(c, http.StatusUnauthorized, response.ErrCodeInvalidToken, "invalid or expired token")
			c.Abort()
			return
		}

		c.Set(ContextUserID, claims.UserID)
		c.Set(ContextUserRoles, claims.Roles)

		c.Next()
	}
}
