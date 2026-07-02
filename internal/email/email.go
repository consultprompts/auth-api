package email

import (
	"fmt"
	"os"

	"github.com/resend/resend-go/v2"
)

type EmailClient struct {
	client *resend.Client
	from   string
}

func NewEmailClient() *EmailClient {
	apiKey := os.Getenv("RESEND_API_KEY")
	from := os.Getenv("RESEND_FROM")

	return &EmailClient{
		client: resend.NewClient(apiKey),
		from:   from,
	}
}

func (email *EmailClient) SendVerificationEmail(to, token string) error {
	verificationURL := fmt.Sprintf(
		"http://localhost:3000/verify-email?token=%s", token,
	)

	params := &resend.SendEmailRequest{
		From:    email.from,
		To:      []string{to},
		Subject: "Verify your email — consultprompts.com",
		Html: fmt.Sprintf(`
			<h2>Welcome to consultprompts.com</h2>
			<p>Click the link below to verify your email address:</p>
			<a href="%s">Verify Email</a>
			<p>This link expires in 24 hours.</p>
			<p>If you didn't create an account, you can safely ignore this email.</p>
		`, verificationURL),
	}

	_, err := email.client.Emails.Send(params)
	return err
}

func (email *EmailClient) SendPasswordResetEmail(to, token string) error {
	resetURL := fmt.Sprintf(
		"http://localhost:3000/reset-password?token=%s", token,
	)

	params := &resend.SendEmailRequest{
		From:    email.from,
		To:      []string{to},
		Subject: "Reset your password — consultprompts.com",
		Html: fmt.Sprintf(`
			<h2>Password Reset Request</h2>
			<p>Click the link below to reset your password:</p>
			<a href="%s">Reset Password</a>
			<p>This link expires in 1 hour.</p>
			<p>If you didn't request a password reset, you can safely ignore this email.</p>
		`, resetURL),
	}

	_, err := email.client.Emails.Send(params)
	return err
}

func (e *EmailClient) SendLoginNotificationEmail(to string) error {
	params := &resend.SendEmailRequest{
		From:    e.from,
		To:      []string{to},
		Subject: "New login detected — consultprompts.com",
		Html: `
			<h2>New login to your account</h2>
			<p>We detected a new login to your consultprompts.com account.</p>
			<p>If this was you, no action is needed.</p>
			<p>If this wasn't you, <a href="http://localhost:3000/reset-password">reset your password immediately</a>.</p>
		`,
	}

	_, err := e.client.Emails.Send(params)
	return err
}
