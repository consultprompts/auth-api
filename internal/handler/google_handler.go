package handler

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/consultprompts/auth-service/internal/response"
	"github.com/gin-gonic/gin"
)

const (
	googleAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL    = "https://oauth2.googleapis.com/token"
	oauthStateCookie  = "g_oauth_state"
	oauthStateTTL     = 10 * time.Minute
	googleHTTPTimeout = 10 * time.Second
)

type googleConfig struct {
	clientID     string
	clientSecret string
	redirectURL  string
	frontendURL  string
}

func loadGoogleConfig() (*googleConfig, error) {
	cfg := &googleConfig{
		clientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		clientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		redirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		frontendURL:  os.Getenv("FRONTEND_URL"),
	}
	if cfg.clientID == "" || cfg.clientSecret == "" {
		return nil, fmt.Errorf("google auth not configured")
	}
	if cfg.redirectURL == "" {
		cfg.redirectURL = "http://localhost:8080/auth/google/callback"
	}
	if cfg.frontendURL == "" {
		cfg.frontendURL = "http://localhost:3000"
	}
	return cfg, nil
}

// GoogleLogin starts the OAuth flow: sets an anti-CSRF state cookie and
// redirects the browser to Google's consent screen.
func (h *AuthHandler) GoogleLogin(c *gin.Context) {
	cfg, err := loadGoogleConfig()
	if err != nil {
		response.RespondError(c, http.StatusServiceUnavailable, response.ErrCodeInternalError, "Google sign-in is not configured")
		return
	}

	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		response.RespondError(c, http.StatusInternalServerError, response.ErrCodeInternalError, "failed to generate state")
		return
	}
	state := hex.EncodeToString(stateBytes)

	secure := strings.HasPrefix(cfg.redirectURL, "https://")
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(oauthStateCookie, state, int(oauthStateTTL.Seconds()), "/", "", secure, true)

	params := url.Values{
		"client_id":     {cfg.clientID},
		"redirect_uri":  {cfg.redirectURL},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"state":         {state},
		"prompt":        {"select_account"},
	}
	c.Redirect(http.StatusFound, googleAuthURL+"?"+params.Encode())
}

// GoogleCallback finishes the flow: verifies state, exchanges the code for an
// ID token, upserts the user, and hands tokens to the SPA via URL fragment
// (fragments are never sent to servers or written to access logs).
func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	cfg, err := loadGoogleConfig()
	if err != nil {
		response.RespondError(c, http.StatusServiceUnavailable, response.ErrCodeInternalError, "Google sign-in is not configured")
		return
	}

	fail := func(reason string) {
		slog.Warn("google oauth callback failed", "reason", reason)
		c.Redirect(http.StatusFound, cfg.frontendURL+"/auth/callback#error="+url.QueryEscape(reason))
	}

	// Verify anti-CSRF state.
	cookieState, err := c.Cookie(oauthStateCookie)
	queryState := c.Query("state")
	c.SetCookie(oauthStateCookie, "", -1, "/", "", false, true)
	if err != nil || queryState == "" ||
		subtle.ConstantTimeCompare([]byte(cookieState), []byte(queryState)) != 1 {
		fail("invalid_state")
		return
	}

	code := c.Query("code")
	if code == "" {
		fail("missing_code")
		return
	}

	// Exchange the authorization code for tokens.
	client := &http.Client{Timeout: googleHTTPTimeout}
	resp, err := client.PostForm(googleTokenURL, url.Values{
		"code":          {code},
		"client_id":     {cfg.clientID},
		"client_secret": {cfg.clientSecret},
		"redirect_uri":  {cfg.redirectURL},
		"grant_type":    {"authorization_code"},
	})
	if err != nil {
		fail("token_exchange_failed")
		return
	}
	defer resp.Body.Close()

	var tokenResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil || tokenResp.IDToken == "" {
		fail("token_exchange_failed")
		return
	}

	// The ID token came directly from Google's token endpoint over TLS, so
	// its payload can be trusted without local signature verification.
	claims, err := decodeIDTokenClaims(tokenResp.IDToken)
	if err != nil {
		fail("invalid_id_token")
		return
	}
	if claims.Aud != cfg.clientID {
		fail("invalid_id_token")
		return
	}
	if claims.Email == "" || !claims.EmailVerified {
		fail("email_not_verified")
		return
	}

	accessToken, refreshToken, err := h.authService.LoginWithGoogle(c.Request.Context(), strings.ToLower(claims.Email))
	if err != nil {
		slog.Error("google login failed", "error", err)
		fail("login_failed")
		return
	}

	fragment := url.Values{
		"access_token":  {accessToken},
		"refresh_token": {refreshToken},
		"email":         {claims.Email},
	}
	c.Redirect(http.StatusFound, cfg.frontendURL+"/auth/callback#"+fragment.Encode())
}

type googleIDClaims struct {
	Aud           string `json:"aud"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

func decodeIDTokenClaims(idToken string) (*googleIDClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed id token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims googleIDClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return &claims, nil
}
