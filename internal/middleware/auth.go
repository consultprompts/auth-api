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

func RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		roles, exists := c.Get(ContextUserRoles)
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "FORBIDDEN",
					"message": "insufficient permissions",
				},
			})
			c.Abort()
			return
		}

		userRoles, ok := roles.([]string)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"error": gin.H{
					"code":    "FORBIDDEN",
					"message": "insufficient permissions",
				},
			})
			c.Abort()
			return
		}

		for _, r := range userRoles {
			if r == role {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"error": gin.H{
				"code":    "FORBIDDEN",
				"message": "insufficient permissions",
			},
		})
		c.Abort()
	}
}
