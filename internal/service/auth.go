package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/g-villarinho/user-demo/config"
	"github.com/g-villarinho/user-demo/infra/notification"
	"github.com/g-villarinho/user-demo/internal/domain"
	"github.com/g-villarinho/user-demo/internal/model"
	"github.com/g-villarinho/user-demo/internal/repository"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	VerfiyEmailExpirationMinute = 10 * time.Minute
)

type AuthService interface {
	RegisterAccount(ctx context.Context, name, email, password string) error
	VerifyEmail(ctx context.Context, token uuid.UUID) (*model.AccessToken, error)
	Login(ctx context.Context, email, password string) (*model.AccessToken, error)
	UpdatePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error
	RequestChangeEmail(ctx context.Context, userID uuid.UUID, newEmail string) error
	ChangeEmail(ctx context.Context, token uuid.UUID) error
	RequestPasswordReset(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token uuid.UUID, newPassword string) (*model.AccessToken, error)
}

type authService struct {
	userRepo              repository.UserRepository
	verificationTokenRepo repository.VerificationTokenRepository
	jwtService            JwtService
	config                *config.Config
	logger                *slog.Logger
	emailNotification     notification.EmailNotification
}

func NewAuthService(
	userRepo repository.UserRepository,
	verificationTokenRepo repository.VerificationTokenRepository,
	jwtService JwtService,
	config *config.Config,
	logger *slog.Logger,
	emailNotification notification.EmailNotification,
) AuthService {
	return &authService{
		userRepo:              userRepo,
		verificationTokenRepo: verificationTokenRepo,
		jwtService:            jwtService,
		config:                config,
		logger:                logger.With(slog.String("service", "auth")),
		emailNotification:     emailNotification,
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
		return domain.ErrEmailAlreadyExists
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	user := domain.NewUser(name, email, string(passwordHash))

	if err := s.userRepo.Create(ctx, user); err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	expiresAt := time.Now().UTC().Add(VerfiyEmailExpirationMinute)
	verificationCode := domain.NewVerificationCode(user.ID, domain.VerificationEmailFlow, expiresAt, "")

	if err := s.verificationTokenRepo.Create(ctx, verificationCode); err != nil {
		return fmt.Errorf("create verification code for userId %s: %w", user.ID.String(), err)
	}

	url := s.getVerificationTokenURL(verificationCode.ID, verificationCode.Flow)

	go func() {
		err := s.emailNotification.SendWelcomeEmail(context.Background(), user.CreatedAt, user.Name, url, user.Email)
		if err != nil {
			logger.Error("failed to send welcome email",
				slog.String("userId", user.ID.String()),
				slog.String("error", err.Error()),
			)
		}
		logger.Debug("email sent successfully")
	}()

	return nil
}

func (s *authService) VerifyEmail(ctx context.Context, token uuid.UUID) (*model.AccessToken, error) {
	verificationToken, err := s.verificationTokenRepo.FindByID(ctx, token)
	if err != nil {
		if errors.Is(err, repository.ErrVerificationCodeNotFound) {
			return nil, domain.ErrVerificationTokenNotFound
		}

		return nil, fmt.Errorf("find verification token by id %s: %w", token, err)
	}

	if verificationToken.IsExpired() || !verificationToken.IsVerificationEmailFlow() {
		return nil, domain.ErrInvalidVerificationToken
	}

	if err := s.userRepo.VerifyEmail(ctx, verificationToken.UserID); err != nil {
		return nil, fmt.Errorf("verify user email for userId %s: %w", verificationToken.UserID, err)
	}

	if err := s.verificationTokenRepo.Delete(ctx, verificationToken.ID); err != nil {
		return nil, fmt.Errorf("delete verificationCode with id %s: %w", verificationToken.ID, err)
	}

	accessToken, err := s.jwtService.GenerateAccessTokenJWT(ctx, verificationToken.UserID)
	if err != nil {
		return nil, fmt.Errorf("generate accessToken for userId %s: %w", verificationToken.UserID, err)
	}

	return accessToken, nil
}

func (s *authService) Login(ctx context.Context, email string, password string) (*model.AccessToken, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil, domain.ErrInvalidCredentials
		}

		return nil, fmt.Errorf("find user by email: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	if user.IsBlocked() {
		return nil, domain.ErrUserBlocked
	}

	if !user.IsEmailVerified() {
		if err := s.sendVerificationEmail(ctx, user); err != nil {
			return nil, fmt.Errorf("handle unverified email: %w", err)
		}

		return nil, domain.ErrEmailNotVerified
	}

	accessToken, err := s.jwtService.GenerateAccessTokenJWT(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("generate access token for userId %s: %w", user.ID, err)
	}

	return accessToken, nil
}

func (s *authService) UpdatePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return domain.ErrUserNotFound
		}

		return fmt.Errorf("find user by id %s: %w", userID, err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword))
	if err != nil {
		return domain.ErrPasswordMismatch
	}

	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	if err := s.userRepo.UpdatePassword(ctx, userID, string(newPasswordHash)); err != nil {
		return fmt.Errorf("update password for userId %s: %w", userID, err)
	}

	return nil
}

func (s *authService) RequestChangeEmail(ctx context.Context, userID uuid.UUID, newEmail string) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return domain.ErrUserNotFound
		}

		return fmt.Errorf("find user by id %s: %w", userID, err)
	}

	if user.Email == newEmail {
		return domain.ErrEmailIsTheSame
	}

	exists, err := s.userRepo.ExistsByEmail(ctx, newEmail)
	if err != nil {
		return fmt.Errorf("check if email %s already exists: %w", newEmail, err)
	}

	if exists {
		return domain.ErrEmailInUse
	}

	verificationToken := domain.NewVerificationCode(userID, domain.ChangeEmailFlow, time.Now().UTC().Add(VerfiyEmailExpirationMinute), newEmail)

	if err := s.verificationTokenRepo.Create(ctx, verificationToken); err != nil {
		return fmt.Errorf("create verification token for change email for userId %s: %w", userID, err)
	}

	url := s.getVerificationTokenURL(verificationToken.ID, verificationToken.Flow)

	fmt.Println()
	fmt.Println(url)
	fmt.Println()

	return nil
}

func (s *authService) ChangeEmail(ctx context.Context, token uuid.UUID) error {
	verificationToken, err := s.verificationTokenRepo.FindByID(ctx, token)
	if err != nil {
		if errors.Is(err, repository.ErrVerificationCodeNotFound) {
			return domain.ErrVerificationTokenNotFound
		}

		return fmt.Errorf("find verification token by id %s: %w", token, err)
	}

	if verificationToken.IsExpired() || !verificationToken.IsChangeEmailFlow() {
		return domain.ErrInvalidVerificationToken
	}

	if !verificationToken.Payload.Valid {
		return domain.ErrInvalidVerificationTokenPayload
	}

	newEmail := verificationToken.Payload.String

	if err := s.userRepo.UpdateEmail(ctx, verificationToken.UserID, newEmail); err != nil {
		return fmt.Errorf("update email for userId %s: %w", verificationToken.UserID, err)
	}

	if err := s.verificationTokenRepo.Delete(ctx, verificationToken.ID); err != nil {
		return fmt.Errorf("delete verification token with id %s: %w", verificationToken.ID, err)
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

	verificationToken := domain.NewVerificationCode(user.ID, domain.ResetPasswordFlow, time.Now().UTC().Add(VerfiyEmailExpirationMinute), "")
	if err := s.verificationTokenRepo.Create(ctx, verificationToken); err != nil {
		return fmt.Errorf("create verification token for reset password for userId %s: %w", user.ID, err)
	}

	url := s.getVerificationTokenURL(verificationToken.ID, verificationToken.Flow)

	go func() {
		err := s.emailNotification.SendResetPasswordEmail(context.Background(), user.Name, url, user.Email)
		if err != nil {
			logger.Error("failed to send reset password email",
				slog.String("userId", user.ID.String()),
				slog.String("error", err.Error()),
			)
		}
		logger.Debug("email send successfully")
	}()

	return nil
}

func (s *authService) ResetPassword(ctx context.Context, token uuid.UUID, newPassword string) (*model.AccessToken, error) {
	verificationToken, err := s.verificationTokenRepo.FindByID(ctx, token)
	if err != nil {
		if errors.Is(err, repository.ErrVerificationCodeNotFound) {
			return nil, domain.ErrVerificationTokenNotFound
		}

		return nil, fmt.Errorf("find verification token by id %s: %w", token, err)
	}

	if verificationToken.IsExpired() || !verificationToken.IsResetPasswordFlow() {
		return nil, domain.ErrInvalidVerificationToken
	}

	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash new password: %w", err)
	}

	if err := s.userRepo.UpdatePassword(ctx, verificationToken.UserID, string(newPasswordHash)); err != nil {
		return nil, fmt.Errorf("update password for userId %s: %w", verificationToken.UserID, err)
	}

	if err := s.verificationTokenRepo.Delete(ctx, verificationToken.ID); err != nil {
		return nil, fmt.Errorf("delete verification token with id %s: %w", verificationToken.ID, err)
	}

	return nil, nil
}

// Private methods

func (s *authService) getVerificationTokenURL(token uuid.UUID, flow domain.VerificationTokenFlow) string {
	var baseURL string
	var path string

	switch flow {
	case domain.VerificationEmailFlow:
		baseURL = s.config.URL.APIBaseURL
		path = "/api/v1/auth/verify-email"
	case domain.ResetPasswordFlow:
		baseURL = s.config.URL.APPBaseURL
		path = "/reset-password"
	case domain.ChangeEmailFlow:
		baseURL = s.config.URL.APIBaseURL
		path = "/api/v1/auth/change-email"
	default:
		baseURL = s.config.URL.APIBaseURL
		path = "/api/v1/auth/verify"
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
	q.Set("token", token.String())
	parsedURL.RawQuery = q.Encode()

	return parsedURL.String()
}

func (s *authService) sendVerificationEmail(ctx context.Context, user *domain.User) error {
	logger := s.logger.With(
		slog.String("method", "sendVerificationEmail"),
		slog.String("userID", user.ID.String()),
	)

	verificationToken, err := s.verificationTokenRepo.FindValidByUserIDAndFlow(ctx, user.ID, domain.VerificationEmailFlow)
	if err != nil && !errors.Is(err, repository.ErrVerificationCodeNotFound) {
		return fmt.Errorf("find existing verification token: %w", err)
	}

	if verificationToken != nil && !verificationToken.IsExpired() {
		url := s.getVerificationTokenURL(verificationToken.ID, verificationToken.Flow)
		go func() {
			err := s.emailNotification.SendWelcomeEmail(context.Background(), user.CreatedAt, user.Name, url, user.Email)
			if err != nil {
				logger.Error("failed to send welcome email",
					slog.String("error", err.Error()),
				)
			}
			logger.Debug("email sent successfully")
		}()
		return nil
	}

	if err := s.verificationTokenRepo.InvalidateByUserIDAndFlow(ctx, user.ID, domain.VerificationEmailFlow); err != nil {
		return fmt.Errorf("invalidate old verification tokens: %w", err)
	}

	expiresAt := time.Now().UTC().Add(VerfiyEmailExpirationMinute)
	newVerificationToken := domain.NewVerificationCode(user.ID, domain.VerificationEmailFlow, expiresAt, "")

	if err := s.verificationTokenRepo.Create(ctx, newVerificationToken); err != nil {
		return fmt.Errorf("create verification code for userId %s: %w", user.ID.String(), err)
	}

	url := s.getVerificationTokenURL(newVerificationToken.ID, newVerificationToken.Flow)

	go func() {
		err := s.emailNotification.SendWelcomeEmail(context.Background(), user.CreatedAt, user.Name, url, user.Email)
		if err != nil {
			logger.Error("failed to send welcome email",
				slog.String("error", err.Error()),
			)
		}
		logger.Debug("email sent successfully")
	}()

	return nil
}
