package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// RequestLogger emits one structured JSON log entry per request.
func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		if raw := c.Request.URL.RawQuery; raw != "" {
			path = path + "?" + raw
		}

		c.Next()

		level := slog.LevelInfo
		if c.Writer.Status() >= http.StatusInternalServerError {
			level = slog.LevelError
		} else if c.Writer.Status() >= http.StatusBadRequest {
			level = slog.LevelWarn
		}

		slog.LogAttrs(c.Request.Context(), level, "request",
			slog.String("method", c.Request.Method),
			slog.String("path", path),
			slog.Int("status", c.Writer.Status()),
			slog.String("client_ip", c.ClientIP()),
			slog.Duration("duration", time.Since(start)),
		)
	}
}

// Recovery recovers from panics and logs them as structured JSON instead of
// gin's default plain-text stack dump.
func Recovery() gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(io.Discard, func(c *gin.Context, recovered any) {
		slog.Error("Panic recovered",
			"error", recovered,
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
		)
		c.AbortWithStatus(http.StatusInternalServerError)
	})
}
