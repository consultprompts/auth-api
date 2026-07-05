package email

import (
	"log/slog"
	"os"

	shared "github.com/consultprompts/shared/email"
)

// Client adapts the shared email client to the EmailClient interface expected
// by auth-service. It reads FRONTEND_URL from env so callers don't have to.
type Client struct {
	shared      *shared.Client
	frontendURL string
}

// NewEmailClient returns nil when email is not configured so callers can treat
// it as optional. Logs a warning at startup.
func NewEmailClient() *Client {
	sharedClient := shared.NewClient()
	if sharedClient == nil {
		slog.Warn("Email notifications disabled — set RESEND_API_KEY and RESEND_FROM to enable")
		return nil
	}

	url := os.Getenv("FRONTEND_URL")
	if url == "" {
		url = "http://localhost:3000"
	}
	return &Client{
		shared:      sharedClient,
		frontendURL: url,
	}
}

func (c *Client) SendVerificationEmail(to, token string) error {
	return c.shared.SendVerificationEmail(to, token, c.frontendURL)
}

func (c *Client) SendPasswordResetEmail(to, token string) error {
	return c.shared.SendPasswordResetEmail(to, token, c.frontendURL)
}

func (c *Client) SendLoginNotificationEmail(to string) error {
	return c.shared.SendLoginNotificationEmail(to, c.frontendURL)
}
