package email

import (
	"os"

	shared "github.com/consultprompts/shared/email"
)

// Client adapts the shared email client to the EmailClient interface expected
// by auth-service. It reads FRONTEND_URL from env so callers don't have to.
type Client struct {
	shared      *shared.Client
	frontendURL string
}

func NewEmailClient() *Client {
	url := os.Getenv("FRONTEND_URL")
	if url == "" {
		url = "http://localhost:3000"
	}
	return &Client{
		shared:      shared.NewClient(),
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
