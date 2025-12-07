package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/g-villarinho/base-project/config"
	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/g-villarinho/base-project/internal/infra/notification"
	"github.com/g-villarinho/base-project/internal/repository"
	"github.com/google/uuid"
)

const (
	VerfiyEmailExpirationMinute = 10 * time.Minute
)

type VerificationService interface {
	CreateVerification(ctx context.Context, userID uuid.UUID, flow domain.VerificationFlow, payload string) (*domain.Verification, error)
	ConsumeVerificationToken(ctx context.Context, token string, expectedFlow domain.VerificationFlow) (*domain.Verification, error)
	GenerateVerificationURL(token string, flow domain.VerificationFlow) string
	SendVerificationEmail(ctx context.Context, user *domain.User, flow domain.VerificationFlow) error
	InvalidateUserVerifications(ctx context.Context, userID uuid.UUID, flow domain.VerificationFlow) error
}

type verificationService struct {
	verificationRepo  repository.VerificationRepository
	emailNotification notification.EmailNotification
	URLConfig         config.URL
	logger            *slog.Logger
}

func NewVerificationService(
	verificationRepo repository.VerificationRepository,
	emailNotification notification.EmailNotification,
	config *config.Config,
) VerificationService {
	return &verificationService{
		verificationRepo:  verificationRepo,
		emailNotification: emailNotification,
		URLConfig:         config.URL,
	}
}

func (s *verificationService) CreateVerification(ctx context.Context, userID uuid.UUID, flow domain.VerificationFlow, payload string) (*domain.Verification, error) {
	expiresAt := time.Now().UTC().Add(VerfiyEmailExpirationMinute)
	verification, err := domain.NewVerification(userID, flow, expiresAt, payload)
	if err != nil {
		return nil, fmt.Errorf("create verification entity: %w", err)
	}

	if err := s.verificationRepo.Create(ctx, verification); err != nil {
		return nil, fmt.Errorf("create verification: %w", err)
	}

	return verification, nil
}

func (s *verificationService) ConsumeVerificationToken(ctx context.Context, token string, expectedFlow domain.VerificationFlow) (*domain.Verification, error) {
	verification, err := s.verificationRepo.FindByToken(ctx, token)
	if err != nil {
		if errors.Is(err, repository.ErrVerificationNotFound) {
			return nil, domain.ErrVerificationNotFound
		}

		return nil, fmt.Errorf("find verification by token: %w", err)
	}

	if verification.IsExpired() {
		return nil, domain.ErrInvalidVerification
	}

	if verification.Flow != expectedFlow {
		return nil, domain.ErrInvalidVerification
	}

	if err := s.verificationRepo.Delete(ctx, verification.ID); err != nil {
		return nil, fmt.Errorf("delete verification: %w", err)
	}

	return verification, nil
}

func (s *verificationService) GenerateVerificationURL(token string, flow domain.VerificationFlow) string {
	baseURL := s.URLConfig.APPBaseURL
	var path string

	switch flow {
	case domain.VerificationEmailFlow:
		path = "/auth/verify-email"
	case domain.ResetPasswordFlow:
		path = "/auth/reset-password"
	case domain.ChangeEmailFlow:
		path = "/auth/change-email"
	default:
		path = "/auth/verify"
	}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		parsedURL = &url.URL{
			Scheme: "http",
			Host:   "localhost",
		}
	}

	parsedURL.Path = path
	q := parsedURL.Query()
	q.Set("token", token)
	parsedURL.RawQuery = q.Encode()

	return parsedURL.String()
}

func (s *verificationService) SendVerificationEmail(ctx context.Context, user *domain.User, flow domain.VerificationFlow) error {
	verification, err := s.verificationRepo.FindValidByUserIDAndFlow(ctx, user.ID, flow)
	if err != nil && !errors.Is(err, repository.ErrVerificationNotFound) {
		return fmt.Errorf("find valid verification by user id and flow: %w", err)
	}

	if verification != nil && !verification.IsExpired() {
		verificationURL := s.GenerateVerificationURL(verification.Token, verification.Flow)
		s.sendEmailAsync(user, verificationURL, verification)
		return nil
	}

	if err := s.verificationRepo.DeleteByUserIDAndFlow(ctx, user.ID, flow); err != nil {
		return fmt.Errorf("invalidate verification tokens for userId: %w", err)
	}

	newVerification, err := s.CreateVerification(ctx, user.ID, flow, "")
	if err != nil {
		return fmt.Errorf("create new verification: %w", err)
	}

	verificationURL := s.GenerateVerificationURL(newVerification.Token, newVerification.Flow)
	s.sendEmailAsync(user, verificationURL, newVerification)

	return nil
}

func (s *verificationService) InvalidateUserVerifications(ctx context.Context, userID uuid.UUID, flow domain.VerificationFlow) error {
	if err := s.verificationRepo.DeleteByUserIDAndFlow(ctx, userID, flow); err != nil {
		return fmt.Errorf("invalidate verification tokens for userId %s: %w", userID, err)
	}
	return nil
}

// REGION: Private methods

func (s *verificationService) sendEmailAsync(user *domain.User, verificationURL string, verification *domain.Verification) {
	logger := s.logger.With(
		slog.String("method", "sendEmailAsync"),
		slog.String("userID", user.ID.String()),
		slog.String("flow", string(verification.Flow)),
	)

	go func() {
		var err error
		switch verification.Flow {
		case domain.VerificationEmailFlow:
			err = s.emailNotification.SendWelcomeEmail(context.Background(), user.CreatedAt, user.Name, verificationURL, user.Email)
		case domain.ResetPasswordFlow:
			err = s.emailNotification.SendResetPasswordEmail(context.Background(), user.Name, verificationURL, user.Email)
		case domain.ChangeEmailFlow:
			if verification.Payload == nil {
				logger.Warn("missing payload for change email flow")
				return
			}
			newEmail := *verification.Payload
			err = s.emailNotification.SendChangeEmailNotification(context.Background(), user.Name, newEmail, verificationURL, user.Email)
		default:
			logger.Warn("unsupported email flow")
			return
		}

		if err != nil {
			logger.Error("failed to send email", slog.String("error", err.Error()))
		}
	}()
}

// ENDREGION
