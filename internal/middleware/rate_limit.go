package middleware

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/consultprompts/auth-service/internal/response"
	"github.com/gin-gonic/gin"
)

type lockoutEntry struct {
	failedAttempts int
	lockedUntil    time.Time
	lastAttempt    time.Time
}

type LoginProtection struct {
	mu      sync.Mutex
	entries map[string]*lockoutEntry
}

func NewLoginProtection() *LoginProtection {
	lp := &LoginProtection{
		entries: make(map[string]*lockoutEntry),
	}
	go lp.CleanupLoop()
	return lp
}

func (lp *LoginProtection) lockoutDuration(failedAttempts int) time.Duration {
	switch {
	case failedAttempts >= 10:
		return 10 * time.Minute
	case failedAttempts >= 7:
		return 3 * time.Minute
	case failedAttempts >= 5:
		return 1 * time.Minute
	default:
		return 0
	}
}

func (lp *LoginProtection) GetEntry(ip string) *lockoutEntry {
	entry, exists := lp.entries[ip]
	if !exists {
		entry = &lockoutEntry{}
		lp.entries[ip] = entry
	}
	return entry
}

func (lp *LoginProtection) CleanupLoop() {
	for {
		time.Sleep(15 * time.Minute)
		lp.mu.Lock()
		for ip, entry := range lp.entries {
			if time.Since(entry.lastAttempt) > 30*time.Minute {
				delete(lp.entries, ip)
			}
		}
		lp.mu.Unlock()
	}
}

func (lp *LoginProtection) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		lp.mu.Lock()
		entry := lp.GetEntry(ip)

		// check if currently locked out
		if time.Now().Before(entry.lockedUntil) {
			waitSeconds := int(time.Until(entry.lockedUntil).Seconds())
			lp.mu.Unlock()
			response.RespondError(c, http.StatusTooManyRequests, response.ErrCodeTooManyRequests,
				fmt.Sprintf("too many failed attempts, please try again in %d seconds", waitSeconds))
			c.Abort()
			return
		}

		lp.mu.Unlock()

		// let the request through
		c.Next()

		// check what happened AFTER the handler ran
		if c.Writer.Status() == http.StatusUnauthorized {
			lp.mu.Lock()
			entry := lp.GetEntry(ip)
			entry.failedAttempts++
			entry.lastAttempt = time.Now()

			lockout := lp.lockoutDuration(entry.failedAttempts)
			if lockout > 0 {
				entry.lockedUntil = time.Now().Add(lockout)
			}
			lp.mu.Unlock()
		} else if c.Writer.Status() == http.StatusOK {
			// successful login — reset the counter
			lp.mu.Lock()
			delete(lp.entries, ip)
			lp.mu.Unlock()
		}
	}
}
