package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/g-villarinho/base-project/internal/model"
	"github.com/g-villarinho/base-project/internal/repository"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
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
	Logout(ctx context.Context, userID, sessionID uuid.UUID) error
}

type authService struct {
	userRepository      repository.UserRepository
	verificationService VerificationService
	sessionService      SessionService
	logger              *slog.Logger
}

func NewAuthService(
	userRepository repository.UserRepository,
	verificationService VerificationService,
	sessionService SessionService,
	logger *slog.Logger,
) AuthService {
	return &authService{
		userRepository:      userRepository,
		verificationService: verificationService,
		sessionService:      sessionService,
		logger:              logger.With(slog.String("service", "auth")),
	}
}

func (s *authService) RegisterAccount(ctx context.Context, name string, email string, password string) error {
	userExists, err := s.userRepository.ExistsByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("authService.RegisterAccount: %w", err)
	}

	if userExists {
		return domain.ErrEmailAlreadyExists
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("authService.RegisterAccount: hash password: %w", err)
	}

	user := domain.NewUser(name, email, string(passwordHash))

	if err := s.userRepository.Create(ctx, user); err != nil {
		return fmt.Errorf("authService.RegisterAccount: %w", err)
	}

	if err := s.verificationService.SendVerificationEmail(ctx, user, domain.VerificationEmailFlow); err != nil {
		return fmt.Errorf("authService.RegisterAccount: %w", err)
	}

	return nil
}

func (s *authService) VerifyEmail(ctx context.Context, input model.VerifyEmailInput) (*domain.Session, error) {
	verification, err := s.verificationService.ValidateAndConsume(ctx, input.Token, domain.VerificationEmailFlow)
	if err != nil {
		return nil, err
	}

	if err := s.userRepository.VerifyEmail(ctx, verification.UserID); err != nil {
		return nil, fmt.Errorf("verify user email for userId %s: %w", verification.UserID, err)
	}

	session, err := s.sessionService.CreateSession(ctx, verification.UserID, input.IPAddress, input.DeviceName, input.UserAgent)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (s *authService) Login(ctx context.Context, input model.LoginInput) (*domain.LoginResult, error) {
	user, err := s.userRepository.FindByEmail(ctx, input.Email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil, domain.ErrInvalidCredentials
		}

		return nil, fmt.Errorf("authService.Login: find user by email: %w", err)
	}

	result := &domain.LoginResult{
		UserID: user.ID,
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)); err != nil {
		return result, domain.ErrInvalidCredentials
	}

	if user.IsBlocked() {
		return result, domain.ErrUserBlocked
	}

	if !user.IsEmailVerified() {
		if err := s.verificationService.SendVerificationEmail(ctx, user, domain.VerificationEmailFlow); err != nil {
			
		}

		return result, domain.ErrEmailNotVerified
	}

	session, err := s.sessionService.CreateSession(ctx, user.ID, input.IPAddress, input.DeviceName, input.UserAgent)
	if err != nil {
		return result, fmt.Errorf("authService.Login: create session: %w", err)
	}

	result.SessionToken = session.Token
	result.SessionExpiresAt = session.ExpiresAt

	return result, nil
}

func (s *authService) UpdatePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error {
	logger := s.logger.With(
		slog.String("method", "UpdatePassword"),
		slog.String("user_id", userID.String()),
	)

	user, err := s.userRepository.FindByID(ctx, userID)
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

	if err := s.userRepository.UpdatePassword(ctx, userID, string(newPasswordHash)); err != nil {
		return fmt.Errorf("update password for userId %s: %w", userID, err)
	}

	return nil
}

func (s *authService) RequestChangeEmail(ctx context.Context, userID uuid.UUID, newEmail string) error {
	logger := s.logger.With(
		slog.String("method", "RequestChangeEmail"),
		slog.String("user_id", userID.String()),
	)

	user, err := s.userRepository.FindByID(ctx, userID)
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

	exists, err := s.userRepository.ExistsByEmail(ctx, newEmail)
	if err != nil {
		return fmt.Errorf("check if email already exists: %w", err)
	}

	if exists {
		logger.Warn("a user with this email already exists")
		return domain.ErrEmailInUse
	}

	verification, err := s.verificationService.CreateVerification(ctx, userID, domain.ChangeEmailFlow, newEmail)
	if err != nil {
		return err
	}

	url := s.verificationService.GenerateVerificationURL(verification.Token, verification.Flow)

	fmt.Println()
	fmt.Println(url)
	fmt.Println()

	return nil
}

func (s *authService) ChangeEmail(ctx context.Context, token string) error {
	logger := s.logger.With(
		slog.String("method", "ChangeEmail"),
	)

	verification, err := s.verificationService.ValidateAndConsume(ctx, token, domain.ChangeEmailFlow)
	if err != nil {
		return err
	}

	if !verification.Payload.Valid {
		logger.Warn("invalid verification payload")
		return domain.ErrInvalidVerificationPayload
	}

	newEmail := verification.Payload.String

	if err := s.userRepository.UpdateEmail(ctx, verification.UserID, newEmail); err != nil {
		logger.Error("failed to update email", slog.String("error", err.Error()))
		return fmt.Errorf("update email for userId %s: %w", verification.UserID, err)
	}

	return nil
}

func (s *authService) RequestPasswordReset(ctx context.Context, email string) error {
	user, err := s.userRepository.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return domain.ErrUserNotFound
		}

		return fmt.Errorf("find user by email %s: %w", email, err)
	}

	if err := s.verificationService.SendVerificationEmail(ctx, user, domain.ResetPasswordFlow); err != nil {
		return fmt.Errorf("send password reset email for userId %s: %w", user.ID, err)
	}

	return nil
}

func (s *authService) ResetPassword(ctx context.Context, token string, newPassword string) (*domain.Session, error) {
	logger := s.logger.With(
		slog.String("method", "ResetPassword"),
		slog.String("token", token),
	)

	verification, err := s.verificationService.ValidateAndConsume(ctx, token, domain.ResetPasswordFlow)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		logger.Error("hash new password", slog.String("error", err.Error()))
		return nil, fmt.Errorf("hash new password: %w", err)
	}

	if err := s.userRepository.UpdatePassword(ctx, verification.UserID, string(newPasswordHash)); err != nil {
		return nil, fmt.Errorf("update password for userId %s: %w", verification.UserID, err)
	}

	return nil, nil
}

func (s *authService) Logout(ctx context.Context, userID, sessionID uuid.UUID) error {
	logger := s.logger.With(
		slog.String("method", "Logout"),
		slog.String("userId", userID.String()),
		slog.String("sessionId", sessionID.String()),
	)

	if err := s.sessionService.DeleteSessionByID(ctx, userID, sessionID); err != nil {
		logger.Error(err.Error())
		return err
	}

	return nil
}
