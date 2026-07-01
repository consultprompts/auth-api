package middleware

import (
	"crypto/rsa"
	"net/http"
	"strings"

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
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid authorization header"})
			c.Abort()
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := jwtpkg.VerifyToken(tokenString, publicKey)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			c.Abort()
			return
		}

		c.Set(ContextUserID, claims.UserID)
		c.Set(ContextUserRoles, claims.Roles)

		c.Next()
	}
}
