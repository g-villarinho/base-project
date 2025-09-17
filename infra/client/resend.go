package client

import (
	"context"
	"fmt"
	"time"

	"github.com/g-villarinho/user-demo/config"
	"github.com/g-villarinho/user-demo/infra/notification"
	"github.com/resend/resend-go/v2"
)

type resendClient struct {
	rc      *resend.Client
	from    string
	timeout time.Duration
}

func NewResendClient(config *config.Config) notification.EmailClient {
	rc := resend.NewClient(config.Resend.APIKey)
	return &resendClient{
		rc:      rc,
		from:    fmt.Sprintf("Acme <noreply@%s>", config.Resend.Domain),
		timeout: config.Resend.Timeout,
	}
}

// SendEmail implements notification.EmailClient.
func (r *resendClient) SendEmail(ctx context.Context, to string, subject string, body string) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	params := &resend.SendEmailRequest{
		From:    r.from,
		To:      []string{to},
		Subject: subject,
		Html:    body,
	}

	_, err := r.rc.Emails.SendWithContext(ctx, params)
	if err != nil {
		return err
	}

	return nil
}
