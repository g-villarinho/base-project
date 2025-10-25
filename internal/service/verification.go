package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/g-villarinho/base-project/config"
	"github.com/g-villarinho/base-project/infra/notification"
	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/g-villarinho/base-project/internal/repository"
	"github.com/google/uuid"
)

const (
	VerfiyEmailExpirationMinute = 10 * time.Minute
)

type VerificationService interface {
	CreateVerification(ctx context.Context, userID uuid.UUID, flow domain.VerificationFlow, payload string) (*domain.Verification, error)
	ValidateAndConsume(ctx context.Context, token string, expectedFlow domain.VerificationFlow) (*domain.Verification, error)
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
	logger *slog.Logger,
) VerificationService {
	return &verificationService{
		verificationRepo:  verificationRepo,
		emailNotification: emailNotification,
		URLConfig:         config.URL,
		logger:            logger.With(slog.String("service", "verification")),
	}
}

func (s *verificationService) CreateVerification(ctx context.Context, userID uuid.UUID, flow domain.VerificationFlow, payload string) (*domain.Verification, error) {
	logger := s.logger.With(
		slog.String("method", "CreateVerification"),
		slog.String("userID", userID.String()),
		slog.String("flow", string(flow)),
	)

	expiresAt := time.Now().UTC().Add(VerfiyEmailExpirationMinute)
	verification, err := domain.NewVerification(userID, flow, expiresAt, payload)
	if err != nil {
		logger.Error("create verification", slog.String("error", err.Error()))
		return nil, fmt.Errorf("create verification for userId %s: %w", userID.String(), err)
	}

	if err := s.verificationRepo.Create(ctx, verification); err != nil {
		return nil, fmt.Errorf("create verification for userId %s: %w", userID.String(), err)
	}

	return verification, nil
}

func (s *verificationService) ValidateAndConsume(ctx context.Context, token string, expectedFlow domain.VerificationFlow) (*domain.Verification, error) {
	logger := s.logger.With(
		slog.String("method", "ValidateAndConsume"),
		slog.String("token", token),
		slog.String("expectedFlow", string(expectedFlow)),
	)

	verification, err := s.verificationRepo.FindByToken(ctx, token)
	if err != nil {
		if errors.Is(err, repository.ErrVerificationNotFound) {
			logger.Warn("verification not found")
			return nil, domain.ErrVerificationNotFound
		}
		return nil, fmt.Errorf("find verification token by id %s: %w", token, err)
	}

	if verification.IsExpired() {
		logger.Warn("verification expired")
		return nil, domain.ErrInvalidVerification
	}

	if verification.Flow != expectedFlow {
		logger.Warn("verification flow mismatch",
			slog.String("expected", string(expectedFlow)),
			slog.String("actual", string(verification.Flow)),
		)
		return nil, domain.ErrInvalidVerification
	}

	if err := s.verificationRepo.Delete(ctx, verification.ID); err != nil {
		return nil, fmt.Errorf("delete verification with id %s: %w", verification.ID, err)
	}

	return verification, nil
}

func (s *verificationService) GenerateVerificationURL(token string, flow domain.VerificationFlow) string {
	var baseURL string
	var path string

	switch flow {
	case domain.VerificationEmailFlow:
		baseURL = s.URLConfig.APIBaseURL
		path = "/auth/verify-email"
	case domain.ResetPasswordFlow:
		baseURL = s.URLConfig.APPBaseURL
		path = "/reset-password"
	case domain.ChangeEmailFlow:
		baseURL = s.URLConfig.APIBaseURL
		path = "/auth/change-email"
	default:
		baseURL = s.URLConfig.APIBaseURL
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
		return fmt.Errorf("find existing verification: %w", err)
	}

	if verification != nil && !verification.IsExpired() {
		verificationURL := s.GenerateVerificationURL(verification.Token, verification.Flow)
		s.sendEmailAsync(user, verificationURL, flow)
		return nil
	}

	if err := s.verificationRepo.InvalidateByUserIDAndFlow(ctx, user.ID, flow); err != nil {
		return fmt.Errorf("invalidate old verification tokens: %w", err)
	}

	newVerification, err := s.CreateVerification(ctx, user.ID, flow, "")
	if err != nil {
		return err
	}

	verificationURL := s.GenerateVerificationURL(newVerification.Token, newVerification.Flow)
	s.sendEmailAsync(user, verificationURL, flow)

	return nil
}

func (s *verificationService) InvalidateUserVerifications(ctx context.Context, userID uuid.UUID, flow domain.VerificationFlow) error {
	if err := s.verificationRepo.InvalidateByUserIDAndFlow(ctx, userID, flow); err != nil {
		return fmt.Errorf("invalidate verification tokens for userId %s: %w", userID, err)
	}
	return nil
}

// Private methods

func (s *verificationService) sendEmailAsync(user *domain.User, verificationURL string, flow domain.VerificationFlow) {
	logger := s.logger.With(
		slog.String("method", "sendEmailAsync"),
		slog.String("userID", user.ID.String()),
		slog.String("flow", string(flow)),
	)

	go func() {
		var err error
		switch flow {
		case domain.VerificationEmailFlow:
			err = s.emailNotification.SendWelcomeEmail(context.Background(), user.CreatedAt, user.Name, verificationURL, user.Email)
		case domain.ResetPasswordFlow:
			err = s.emailNotification.SendResetPasswordEmail(context.Background(), user.Name, verificationURL, user.Email)
		default:
			logger.Warn("unsupported email flow")
			return
		}

		if err != nil {
			logger.Error("failed to send email", slog.String("error", err.Error()))
		} else {
			logger.Debug("email sent successfully")
		}
	}()
}
