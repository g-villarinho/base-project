package notification

import (
	"bytes"
	"context"
	"embed"
	"html/template"
	"time"
)

type EmailClient interface {
	SendEmail(ctx context.Context, to, subject, body string) error
}

//go:embed templates/*
var templateFS embed.FS

type EmailNotification interface {
	SendWelcomeEmail(ctx context.Context, userRegistration time.Time, userName, verificationLink, userEmail string) error
	SendVerifyEmail(ctx context.Context, userName, verificationLink, userEmail string) error
	SendResetPasswordEmail(ctx context.Context, userName, resetLink, userEmail string) error
}

type emailNotification struct {
	emailClient EmailClient
}

func NewEmailNotification(emailClient EmailClient) EmailNotification {
	return &emailNotification{
		emailClient: emailClient,
	}
}

func (e *emailNotification) SendWelcomeEmail(ctx context.Context, userRegistration time.Time, userName, verificationLink, userEmail string) error {
	htmlTemplate, err := template.ParseFS(templateFS, "templates/welcome.html")
	if err != nil {
		return err
	}

	data := struct {
		UserName         string
		RegistrationDate string
		ConfirmationLink string
		CurrentYear      string
		UserEmail        string
	}{
		UserName:         userName,
		RegistrationDate: userRegistration.Format("02/01/2006 às 15:04"),
		ConfirmationLink: verificationLink,
		CurrentYear:      time.Now().Format("2006"),
		UserEmail:        userEmail,
	}

	var htmlBuffer bytes.Buffer
	if err := htmlTemplate.Execute(&htmlBuffer, data); err != nil {
		return err
	}

	subject := "Welcome to ID! Please, verify your email"

	if err := e.emailClient.SendEmail(ctx, userEmail, subject, htmlBuffer.String()); err != nil {
		return err
	}

	return nil
}

func (e *emailNotification) SendVerifyEmail(ctx context.Context, userName, verificationLink, userEmail string) error {
	htmlTemplate, err := template.ParseFS(templateFS, "templates/verify-email.html")
	if err != nil {
		return err
	}

	data := struct {
		UserName         string
		ConfirmationLink string
		CurrentYear      string
		UserEmail        string
	}{
		UserName:         userName,
		ConfirmationLink: verificationLink,
		CurrentYear:      time.Now().Format("2006"),
		UserEmail:        userEmail,
	}

	var htmlBuffer bytes.Buffer
	if err := htmlTemplate.Execute(&htmlBuffer, data); err != nil {
		return err
	}

	subject := "Verify your email address"

	if err := e.emailClient.SendEmail(ctx, userEmail, subject, htmlBuffer.String()); err != nil {
		return err
	}

	return nil
}

func (e *emailNotification) SendResetPasswordEmail(ctx context.Context, userName, resetLink, userEmail string) error {
	htmlTemplate, err := template.ParseFS(templateFS, "templates/reset-password.html")
	if err != nil {
		return err
	}

	data := struct {
		UserName    string
		ResetLink   string
		CurrentYear string
		UserEmail   string
	}{
		UserName:    userName,
		ResetLink:   resetLink,
		CurrentYear: time.Now().Format("2006"),
		UserEmail:   userEmail,
	}

	var htmlBuffer bytes.Buffer
	if err := htmlTemplate.Execute(&htmlBuffer, data); err != nil {
		return err
	}

	subject := "Password Reset Request"

	if err := e.emailClient.SendEmail(ctx, userEmail, subject, htmlBuffer.String()); err != nil {
		return err
	}

	return nil
}
