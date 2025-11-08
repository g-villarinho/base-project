package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/g-villarinho/base-project/internal/repository"
	"github.com/g-villarinho/base-project/pkg/hash"
	"github.com/google/uuid"
)

type AuthService interface {
	RegisterAccount(ctx context.Context, name, email, password string) error
	VerifyEmail(ctx context.Context, token, ipAddress, userAgent, deviceName string) (*domain.Session, error)
	Login(ctx context.Context, email, password, ipAddress, userAgent, deviceName string) (*domain.Session, error)
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
		return fmt.Errorf("check if email exists: %w", err)
	}
	if userExists {
		return domain.ErrEmailAlreadyExists
	}

	passwordHash, err := hash.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	user := domain.NewUser(name, email, passwordHash)
	if err := s.userRepository.Create(ctx, user); err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	if err := s.verificationService.SendVerificationEmail(ctx, user, domain.VerificationEmailFlow); err != nil {
		return fmt.Errorf("send verification email: %w", err)
	}

	return nil
}

func (s *authService) VerifyEmail(ctx context.Context, token, ipAddress, userAgent, deviceName string) (*domain.Session, error) {
	verification, err := s.verificationService.ConsumeVerificationToken(ctx, token, domain.VerificationEmailFlow)
	if err != nil {
		return nil, fmt.Errorf("validate verification token: %w", err)
	}

	if err := s.userRepository.VerifyEmail(ctx, verification.UserID); err != nil {
		return nil, fmt.Errorf("mark email as verified: %w", err)
	}

	session, err := s.sessionService.CreateSession(ctx, verification.UserID, ipAddress, deviceName, userAgent)
	if err != nil {
		return nil, fmt.Errorf("create user session: %w", err)
	}

	return session, nil
}

func (s *authService) Login(ctx context.Context, email, password, ipAddress, userAgent, deviceName string) (*domain.Session, error) {
	user, err := s.userRepository.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, fmt.Errorf("find user by email: %w", err)
	}

	if err := hash.VerifyPassword(password, user.PasswordHash); err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	if user.IsBlocked() {
		return nil, domain.ErrUserBlocked
	}

	if !user.IsEmailVerified() {
		if err := s.verificationService.SendVerificationEmail(ctx, user, domain.VerificationEmailFlow); err != nil {
			return nil, fmt.Errorf("send verification email: %w", err)
		}
		return nil, domain.ErrEmailNotVerified
	}

	session, err := s.sessionService.CreateSession(ctx, user.ID, ipAddress, deviceName, userAgent)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	return session, nil
}

func (s *authService) UpdatePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error {
	user, err := s.userRepository.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return domain.ErrUserNotFound
		}

		return fmt.Errorf("find user by id: %w", err)
	}

	err = hash.VerifyPassword(currentPassword, user.PasswordHash)
	if err != nil {
		return domain.ErrPasswordMismatch
	}

	newPasswordHash, err := hash.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	if err := s.userRepository.UpdatePassword(ctx, userID, newPasswordHash); err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	return nil
}

func (s *authService) RequestChangeEmail(ctx context.Context, userID uuid.UUID, newEmail string) error {
	user, err := s.userRepository.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return domain.ErrUserNotFound
		}
		return fmt.Errorf("find user by id: %w", err)
	}

	if user.Email == newEmail {
		return domain.ErrEmailIsTheSame
	}

	exists, err := s.userRepository.ExistsByEmail(ctx, newEmail)
	if err != nil {
		return fmt.Errorf("check if email exists: %w", err)
	}
	if exists {
		return domain.ErrEmailInUse
	}

	verification, err := s.verificationService.CreateVerification(ctx, userID, domain.ChangeEmailFlow, newEmail)
	if err != nil {
		return fmt.Errorf("create email change verification: %w", err)
	}

	url := s.verificationService.GenerateVerificationURL(verification.Token, verification.Flow)
	fmt.Println()
	fmt.Println(url)
	fmt.Println()

	return nil
}

func (s *authService) ChangeEmail(ctx context.Context, token string) error {
	verification, err := s.verificationService.ConsumeVerificationToken(ctx, token, domain.ChangeEmailFlow)
	if err != nil {
		return fmt.Errorf("consume verification token: %w", err)
	}

	if !verification.Payload.Valid {
		return domain.ErrInvalidVerificationPayload
	}

	newEmail := verification.Payload.String

	if err := s.userRepository.UpdateEmail(ctx, verification.UserID, newEmail); err != nil {
		return fmt.Errorf("update email: %w", err)
	}

	return nil
}

func (s *authService) RequestPasswordReset(ctx context.Context, email string) error {
	user, err := s.userRepository.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return domain.ErrUserNotFound
		}
		return fmt.Errorf("find user by email: %w", err)
	}

	if err := s.verificationService.SendVerificationEmail(ctx, user, domain.ResetPasswordFlow); err != nil {
		return fmt.Errorf("send password reset email: %w", err)
	}

	return nil
}

func (s *authService) ResetPassword(ctx context.Context, token string, newPassword string) (*domain.Session, error) {
	verification, err := s.verificationService.ConsumeVerificationToken(ctx, token, domain.ResetPasswordFlow)
	if err != nil {
		return nil, err
	}

	newPasswordHash, err := hash.HashPassword(newPassword)
	if err != nil {
		return nil, fmt.Errorf("hash new password: %w", err)
	}

	if err := s.userRepository.UpdatePassword(ctx, verification.UserID, newPasswordHash); err != nil {
		return nil, fmt.Errorf("update password for userId %s: %w", verification.UserID, err)
	}

	return nil, nil
}

func (s *authService) Logout(ctx context.Context, userID, sessionID uuid.UUID) error {
	if err := s.sessionService.DeleteSessionByID(ctx, userID, sessionID); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}
