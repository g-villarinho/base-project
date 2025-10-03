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
	"github.com/g-villarinho/base-project/internal/model"
	"github.com/g-villarinho/base-project/internal/repository"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	VerfiyEmailExpirationMinute = 10 * time.Minute
)

type AuthService interface {
	RegisterAccount(ctx context.Context, name, email, password string) error
	VerifyEmail(ctx context.Context, input model.VerifyEmailInput) (*domain.Session, error)
	Login(ctx context.Context, input model.LoginInput) (*domain.Session, error)
	UpdatePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error
	RequestChangeEmail(ctx context.Context, userID uuid.UUID, newEmail string) error
	ChangeEmail(ctx context.Context, token string) error
	RequestPasswordReset(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token string, newPassword string) (*domain.Session, error)
}

type authService struct {
	userRepo          repository.UserRepository
	verificationRepo  repository.VerificationRepository
	emailNotification notification.EmailNotification
	sessionService    SessionService
	URLConfig         config.URL
	logger            *slog.Logger
}

func NewAuthService(
	userRepo repository.UserRepository,
	verificationRepo repository.VerificationRepository,
	emailNotification notification.EmailNotification,
	sessionService SessionService,
	logger *slog.Logger,
	config *config.Config,
) AuthService {
	return &authService{
		userRepo:          userRepo,
		verificationRepo:  verificationRepo,
		emailNotification: emailNotification,
		sessionService:    sessionService,
		URLConfig:         config.URL,
		logger:            logger.With(slog.String("service", "auth")),
	}
}

func (s *authService) RegisterAccount(ctx context.Context, name string, email string, password string) error {
	logger := s.logger.With(
		slog.String("method", "RegisterAccount"),
	)

	userExists, err := s.userRepo.ExistsByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("find user by email: %w", err)
	}

	if userExists {
		logger.Warn("a user with this email already exists")
		return domain.ErrEmailAlreadyExists
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logger.Error("hash password", slog.String("error", err.Error()))
		return fmt.Errorf("hash password: %w", err)
	}

	user := domain.NewUser(name, email, string(passwordHash))

	if err := s.userRepo.Create(ctx, user); err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	expiresAt := time.Now().UTC().Add(VerfiyEmailExpirationMinute)
	verification, err := domain.NewVerification(user.ID, domain.VerificationEmailFlow, expiresAt, "")
	if err != nil {
		logger.Error("create verification", slog.String("error", err.Error()))
		return fmt.Errorf("create verification for userId %s: %w", user.ID.String(), err)
	}

	if err := s.verificationRepo.Create(ctx, verification); err != nil {
		return fmt.Errorf("create verification for userId %s: %w", user.ID.String(), err)
	}

	url := s.getVerificationURL(verification.Token, verification.Flow)

	s.SendWelcomeEmailAsync(user, url)

	return nil
}

func (s *authService) VerifyEmail(ctx context.Context, input model.VerifyEmailInput) (*domain.Session, error) {
	logger := s.logger.With(
		slog.String("method", "VerifyEmail"),
		slog.String("token", input.Token),
	)

	verification, err := s.verificationRepo.FindByToken(ctx, input.Token)
	if err != nil {
		if errors.Is(err, repository.ErrVerificationNotFound) {
			logger.Warn("verification not found")
			return nil, domain.ErrVerificationNotFound
		}

		return nil, fmt.Errorf("find verification token by id %s: %w", input.Token, err)
	}

	if verification.IsExpired() || !verification.IsVerificationEmailFlow() {
		logger.Warn("invalid or expired verification")
		return nil, domain.ErrInvalidVerification
	}

	if err := s.userRepo.VerifyEmail(ctx, verification.UserID); err != nil {
		return nil, fmt.Errorf("verify user email for userId %s: %w", verification.UserID, err)
	}

	if err := s.verificationRepo.Delete(ctx, verification.ID); err != nil {
		return nil, fmt.Errorf("delete verificationCode with id %s: %w", verification.ID, err)
	}

	session, err := s.sessionService.CreateSession(ctx, verification.UserID, input.IPAddress, input.DeviceName, input.UserAgent)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (s *authService) Login(ctx context.Context, input model.LoginInput) (*domain.Session, error) {
	logger := s.logger.With(
		slog.String("method", "Login"),
		slog.String("email", input.Email),
	)

	user, err := s.userRepo.FindByEmail(ctx, input.Email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			logger.Warn("user not found")
			return nil, domain.ErrInvalidCredentials
		}

		logger.Error("failed to find user by email", slog.String("error", err.Error()))
		return nil, fmt.Errorf("find user by email: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)); err != nil {
		logger.Warn("invalid credentials")
		return nil, domain.ErrInvalidCredentials
	}

	if user.IsBlocked() {
		logger.Warn("user is blocked")
		return nil, domain.ErrUserBlocked
	}

	if !user.IsEmailVerified() {
		logger.Warn("email not verified")
		if err := s.sendVerificationEmail(ctx, user); err != nil {
			logger.Error("send verification email", slog.String("error", err.Error()))
			return nil, fmt.Errorf("handle unverified email: %w", err)
		}

		return nil, domain.ErrEmailNotVerified
	}

	session, err := s.sessionService.CreateSession(ctx, user.ID, input.IPAddress, input.DeviceName, input.UserAgent)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (s *authService) UpdatePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error {
	logger := s.logger.With(
		slog.String("method", "UpdatePassword"),
		slog.String("user_id", userID.String()),
	)

	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			logger.Warn("no user found with given ID")
			return domain.ErrUserNotFound
		}

		return fmt.Errorf("find user by id %s: %w", userID, err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword))
	if err != nil {
		logger.Warn("password mismatch")
		return domain.ErrPasswordMismatch
	}

	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		logger.Error("hash new password", slog.String("error", err.Error()))
		return fmt.Errorf("hash new password: %w", err)
	}

	if err := s.userRepo.UpdatePassword(ctx, userID, string(newPasswordHash)); err != nil {
		return fmt.Errorf("update password for userId %s: %w", userID, err)
	}

	return nil
}

func (s *authService) RequestChangeEmail(ctx context.Context, userID uuid.UUID, newEmail string) error {
	logger := s.logger.With(
		slog.String("method", "RequestChangeEmail"),
		slog.String("user_id", userID.String()),
	)

	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			logger.Warn("user not found with given ID")
			return domain.ErrUserNotFound
		}

		return fmt.Errorf("find user by id %s: %w", userID, err)
	}

	if user.Email == newEmail {
		logger.Warn("new email is the same as current email")
		return domain.ErrEmailIsTheSame
	}

	exists, err := s.userRepo.ExistsByEmail(ctx, newEmail)
	if err != nil {
		return fmt.Errorf("check if email already exists: %w", err)
	}

	if exists {
		logger.Warn("a user with this email already exists")
		return domain.ErrEmailInUse
	}

	expiresAt := time.Now().UTC().Add(VerfiyEmailExpirationMinute)

	verification, err := domain.NewVerification(userID, domain.ChangeEmailFlow, expiresAt, newEmail)
	if err != nil {
		logger.Error("create verification", slog.String("error", err.Error()))
		return fmt.Errorf("create verification for change email for userId %s: %w", userID, err)
	}

	if err := s.verificationRepo.Create(ctx, verification); err != nil {
		return fmt.Errorf("create verification for change email for userId %s: %w", userID, err)
	}

	url := s.getVerificationURL(verification.Token, verification.Flow)

	fmt.Println()
	fmt.Println(url)
	fmt.Println()

	return nil
}

func (s *authService) ChangeEmail(ctx context.Context, token string) error {
	logger := s.logger.With(
		slog.String("method", "ChangeEmail"),
	)

	verification, err := s.verificationRepo.FindByToken(ctx, token)
	if err != nil {
		if errors.Is(err, repository.ErrVerificationNotFound) {
			logger.Warn("verification not found")
			return domain.ErrVerificationNotFound
		}

		logger.Error("failed to find verification token", slog.String("error", err.Error()))
		return fmt.Errorf("find verification token by id %s: %w", token, err)
	}

	if verification.IsExpired() || !verification.IsChangeEmailFlow() {
		logger.Warn("invalid or expired verification")
		return domain.ErrInvalidVerification
	}

	if !verification.Payload.Valid {
		logger.Warn("invalid verification payload")
		return domain.ErrInvalidVerificationPayload
	}

	newEmail := verification.Payload.String

	if err := s.userRepo.UpdateEmail(ctx, verification.UserID, newEmail); err != nil {
		logger.Error("failed to update email", slog.String("error", err.Error()))
		return fmt.Errorf("update email for userId %s: %w", verification.UserID, err)
	}

	if err := s.verificationRepo.Delete(ctx, verification.ID); err != nil {
		logger.Error("failed to delete verification", slog.String("error", err.Error()))
		return fmt.Errorf("delete verification token with id %s: %w", verification.ID, err)
	}

	return nil
}

func (s *authService) RequestPasswordReset(ctx context.Context, email string) error {
	logger := s.logger.With(
		slog.String("method", "RequestPasswordReset"),
	)

	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return domain.ErrUserNotFound
		}

		return fmt.Errorf("find user by email %s: %w", email, err)
	}

	verification, err := domain.NewVerification(user.ID, domain.ResetPasswordFlow, time.Now().UTC().Add(VerfiyEmailExpirationMinute), "")
	if err != nil {
		logger.Error("create verification", slog.String("error", err.Error()), slog.String("userId", user.ID.String()))
		return fmt.Errorf("create verification for reset password for userId %s: %w", user.ID, err)
	}

	if err := s.verificationRepo.Create(ctx, verification); err != nil {
		return fmt.Errorf("create verification for reset password for userId %s: %w", user.ID, err)
	}

	url := s.getVerificationURL(verification.Token, verification.Flow)

	go func() {
		err := s.emailNotification.SendResetPasswordEmail(context.Background(), user.Name, url, user.Email)
		if err != nil {
			logger.Error("send reset password email",
				slog.String("userId", user.ID.String()),
				slog.String("error", err.Error()),
			)
		}
		logger.Debug("email send successfully")
	}()

	return nil
}

func (s *authService) ResetPassword(ctx context.Context, token string, newPassword string) (*domain.Session, error) {
	logger := s.logger.With(
		slog.String("method", "ResetPassword"),
		slog.String("token", token),
	)

	verification, err := s.verificationRepo.FindByToken(ctx, token)
	if err != nil {
		if errors.Is(err, repository.ErrVerificationNotFound) {
			logger.Warn("verification not found")
			return nil, domain.ErrVerificationNotFound
		}

		return nil, fmt.Errorf("find verification token by id %s: %w", token, err)
	}

	if verification.IsExpired() || !verification.IsResetPasswordFlow() {
		logger.Warn("invalid or expired verification")
		return nil, domain.ErrInvalidVerification
	}

	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		logger.Error("hash new password", slog.String("error", err.Error()))
		return nil, fmt.Errorf("hash new password: %w", err)
	}

	if err := s.userRepo.UpdatePassword(ctx, verification.UserID, string(newPasswordHash)); err != nil {
		return nil, fmt.Errorf("update password for userId %s: %w", verification.UserID, err)
	}

	if err := s.verificationRepo.Delete(ctx, verification.ID); err != nil {
		return nil, fmt.Errorf("delete verification token with id %s: %w", verification.ID, err)
	}

	return nil, nil
}

// Private methods

func (s *authService) getVerificationURL(token string, flow domain.VerificationFlow) string {
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

func (s *authService) sendVerificationEmail(ctx context.Context, user *domain.User) error {
	verification, err := s.verificationRepo.FindValidByUserIDAndFlow(ctx, user.ID, domain.VerificationEmailFlow)
	if err != nil && !errors.Is(err, repository.ErrVerificationNotFound) {
		return fmt.Errorf("find existing verification: %w", err)
	}

	if verification != nil && !verification.IsExpired() {
		url := s.getVerificationURL(verification.Token, verification.Flow)
		s.SendWelcomeEmailAsync(user, url)
	}

	if err := s.verificationRepo.InvalidateByUserIDAndFlow(ctx, user.ID, domain.VerificationEmailFlow); err != nil {
		return fmt.Errorf("invalidate old verification tokens: %w", err)
	}

	expiresAt := time.Now().UTC().Add(VerfiyEmailExpirationMinute)
	newVerification, err := domain.NewVerification(user.ID, domain.VerificationEmailFlow, expiresAt, "")

	if err != nil {
		return fmt.Errorf("create verification for email for userId %s: %w", user.ID.String(), err)
	}

	if err := s.verificationRepo.Create(ctx, newVerification); err != nil {
		return fmt.Errorf("create verification code for userId %s: %w", user.ID.String(), err)
	}

	url := s.getVerificationURL(newVerification.Token, newVerification.Flow)

	s.SendWelcomeEmailAsync(user, url)

	return nil
}

func (s *authService) SendWelcomeEmailAsync(user *domain.User, url string) {
	logger := s.logger.With(
		slog.String("method", "SendWelcomeEmailAsync"),
		slog.String("userID", user.ID.String()),
	)

	go func() {
		err := s.emailNotification.SendWelcomeEmail(context.Background(), user.CreatedAt, user.Name, url, user.Email)
		if err != nil {
			logger.Error("failed to send welcome email",
				slog.String("error", err.Error()),
			)
		}
	}()
}
