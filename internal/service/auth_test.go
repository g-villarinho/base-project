package service

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/g-villarinho/base-project/config"
	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/g-villarinho/base-project/internal/mocks"
	"github.com/g-villarinho/base-project/internal/model"
	"github.com/g-villarinho/base-project/internal/repository"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

func setupAuthService(t *testing.T) (AuthService, *mocks.UserRepositoryMock, *mocks.VerificationRepositoryMock, *mocks.EmailNotificationMock, *mocks.SessionServiceMock) {
	t.Helper()
	userRepoMock := mocks.NewUserRepositoryMock(t)
	verificationRepoMock := mocks.NewVerificationRepositoryMock(t)
	emailNotificationMock := mocks.NewEmailNotificationMock(t)
	sessionServiceMock := mocks.NewSessionServiceMock(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		URL: config.URL{
			APIBaseURL: "http://localhost:8080",
			APPBaseURL: "http://localhost:3000",
		},
	}

	service := NewAuthService(
		userRepoMock,
		verificationRepoMock,
		emailNotificationMock,
		sessionServiceMock,
		logger,
		cfg,
	)

	return service, userRepoMock, verificationRepoMock, emailNotificationMock, sessionServiceMock
}

func TestAuthService_RegisterAccount(t *testing.T) {
	t.Run("should register account successfully when email does not exist", func(t *testing.T) {
		service, userRepoMock, verificationRepoMock, emailNotificationMock, _ := setupAuthService(t)
		ctx := context.Background()
		name := "John Doe"
		email := "john@example.com"
		password := "password123"

		userRepoMock.On("ExistsByEmail", ctx, email).Return(false, nil)
		userRepoMock.On("Create", ctx, mock.AnythingOfType("*domain.User")).Return(nil)
		verificationRepoMock.On("Create", ctx, mock.AnythingOfType("*domain.Verification")).Return(nil)
		emailNotificationMock.On("SendWelcomeEmail", mock.Anything, mock.Anything, name, mock.Anything, email).Return(nil).Maybe()

		err := service.RegisterAccount(ctx, name, email, password)

		assert.NoError(t, err)
		userRepoMock.AssertExpectations(t)
		verificationRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when email already exists", func(t *testing.T) {
		service, userRepoMock, _, _, _ := setupAuthService(t)
		ctx := context.Background()
		email := "existing@example.com"

		userRepoMock.On("ExistsByEmail", ctx, email).Return(true, nil)

		err := service.RegisterAccount(ctx, "John", email, "password123")

		assert.Error(t, err)
		assert.Equal(t, domain.ErrEmailAlreadyExists, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository fails to check email existence", func(t *testing.T) {
		service, userRepoMock, _, _, _ := setupAuthService(t)
		ctx := context.Background()
		repoErr := errors.New("database error")

		userRepoMock.On("ExistsByEmail", ctx, mock.Anything).Return(false, repoErr)

		err := service.RegisterAccount(ctx, "John", "john@example.com", "password123")

		assert.Error(t, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository fails to create user", func(t *testing.T) {
		service, userRepoMock, _, _, _ := setupAuthService(t)
		ctx := context.Background()
		repoErr := errors.New("database error")

		userRepoMock.On("ExistsByEmail", ctx, mock.Anything).Return(false, nil)
		userRepoMock.On("Create", ctx, mock.AnythingOfType("*domain.User")).Return(repoErr)

		err := service.RegisterAccount(ctx, "John", "john@example.com", "password123")

		assert.Error(t, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository fails to create verification", func(t *testing.T) {
		service, userRepoMock, verificationRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		repoErr := errors.New("database error")

		userRepoMock.On("ExistsByEmail", ctx, mock.Anything).Return(false, nil)
		userRepoMock.On("Create", ctx, mock.AnythingOfType("*domain.User")).Return(nil)
		verificationRepoMock.On("Create", ctx, mock.AnythingOfType("*domain.Verification")).Return(repoErr)

		err := service.RegisterAccount(ctx, "John", "john@example.com", "password123")

		assert.Error(t, err)
		userRepoMock.AssertExpectations(t)
		verificationRepoMock.AssertExpectations(t)
	})
}

func TestAuthService_VerifyEmail(t *testing.T) {
	t.Run("should verify email successfully when token is valid", func(t *testing.T) {
		service, userRepoMock, verificationRepoMock, _, sessionServiceMock := setupAuthService(t)
		ctx := context.Background()
		userID := uuid.New()
		token := "valid-token"
		verification := &domain.Verification{
			ID:        uuid.New(),
			Token:     token,
			UserID:    userID,
			Flow:      domain.VerificationEmailFlow,
			ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
		}
		input := model.VerifyEmailInput{
			Token:      token,
			IPAddress:  "192.168.1.1",
			DeviceName: "Device",
			UserAgent:  "UserAgent",
		}
		expectedSession := &domain.Session{
			ID:     uuid.New(),
			UserID: userID,
		}

		verificationRepoMock.On("FindByToken", ctx, token).Return(verification, nil)
		userRepoMock.On("VerifyEmail", ctx, userID).Return(nil)
		verificationRepoMock.On("Delete", ctx, verification.ID).Return(nil)
		sessionServiceMock.On("CreateSession", ctx, userID, input.IPAddress, input.DeviceName, input.UserAgent).Return(expectedSession, nil)

		session, err := service.VerifyEmail(ctx, input)

		assert.NoError(t, err)
		assert.Equal(t, expectedSession, session)
		verificationRepoMock.AssertExpectations(t)
		userRepoMock.AssertExpectations(t)
		sessionServiceMock.AssertExpectations(t)
	})

	t.Run("should return error when verification is not found", func(t *testing.T) {
		service, _, verificationRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		token := "invalid-token"
		input := model.VerifyEmailInput{Token: token}

		verificationRepoMock.On("FindByToken", ctx, token).Return(nil, repository.ErrVerificationNotFound)

		session, err := service.VerifyEmail(ctx, input)

		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Equal(t, domain.ErrVerificationNotFound, err)
		verificationRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when verification is expired", func(t *testing.T) {
		service, _, verificationRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		token := "expired-token"
		verification := &domain.Verification{
			ID:        uuid.New(),
			Token:     token,
			UserID:    uuid.New(),
			Flow:      domain.VerificationEmailFlow,
			ExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
		}
		input := model.VerifyEmailInput{Token: token}

		verificationRepoMock.On("FindByToken", ctx, token).Return(verification, nil)

		session, err := service.VerifyEmail(ctx, input)

		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Equal(t, domain.ErrInvalidVerification, err)
		verificationRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when verification flow is not email verification", func(t *testing.T) {
		service, _, verificationRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		token := "wrong-flow-token"
		verification := &domain.Verification{
			ID:        uuid.New(),
			Token:     token,
			UserID:    uuid.New(),
			Flow:      domain.ResetPasswordFlow,
			ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
		}
		input := model.VerifyEmailInput{Token: token}

		verificationRepoMock.On("FindByToken", ctx, token).Return(verification, nil)

		session, err := service.VerifyEmail(ctx, input)

		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Equal(t, domain.ErrInvalidVerification, err)
		verificationRepoMock.AssertExpectations(t)
	})
}

func TestAuthService_Login(t *testing.T) {
	t.Run("should login successfully when credentials are valid", func(t *testing.T) {
		service, userRepoMock, _, _, sessionServiceMock := setupAuthService(t)
		ctx := context.Background()
		email := "john@example.com"
		password := "password123"
		passwordHash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		user := &domain.User{
			ID:               uuid.New(),
			Email:            email,
			PasswordHash:     string(passwordHash),
			EmailConfirmedAt: sql.NullTime{Time: time.Now(), Valid: true},
		}
		input := model.LoginInput{
			Email:      email,
			Password:   password,
			IPAddress:  "192.168.1.1",
			DeviceName: "Device",
			UserAgent:  "UserAgent",
		}
		expectedSession := &domain.Session{
			ID:     uuid.New(),
			UserID: user.ID,
		}

		userRepoMock.On("FindByEmail", ctx, email).Return(user, nil)
		sessionServiceMock.On("CreateSession", ctx, user.ID, input.IPAddress, input.DeviceName, input.UserAgent).Return(expectedSession, nil)

		session, err := service.Login(ctx, input)

		assert.NoError(t, err)
		assert.Equal(t, expectedSession, session)
		userRepoMock.AssertExpectations(t)
		sessionServiceMock.AssertExpectations(t)
	})

	t.Run("should return error when user is not found", func(t *testing.T) {
		service, userRepoMock, _, _, _ := setupAuthService(t)
		ctx := context.Background()
		input := model.LoginInput{Email: "nonexistent@example.com", Password: "password123"}

		userRepoMock.On("FindByEmail", ctx, input.Email).Return(nil, repository.ErrUserNotFound)

		session, err := service.Login(ctx, input)

		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Equal(t, domain.ErrInvalidCredentials, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when password is incorrect", func(t *testing.T) {
		service, userRepoMock, _, _, _ := setupAuthService(t)
		ctx := context.Background()
		email := "john@example.com"
		correctPassword := "correctpassword"
		passwordHash, _ := bcrypt.GenerateFromPassword([]byte(correctPassword), bcrypt.DefaultCost)
		user := &domain.User{
			ID:           uuid.New(),
			Email:        email,
			PasswordHash: string(passwordHash),
		}
		input := model.LoginInput{Email: email, Password: "wrongpassword"}

		userRepoMock.On("FindByEmail", ctx, email).Return(user, nil)

		session, err := service.Login(ctx, input)

		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Equal(t, domain.ErrInvalidCredentials, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when user is blocked", func(t *testing.T) {
		service, userRepoMock, _, _, _ := setupAuthService(t)
		ctx := context.Background()
		email := "blocked@example.com"
		password := "password123"
		passwordHash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		user := &domain.User{
			ID:           uuid.New(),
			Email:        email,
			PasswordHash: string(passwordHash),
			Status:       domain.BlockedStatus,
			BlockedAt:    sql.NullTime{Time: time.Now(), Valid: true},
		}
		input := model.LoginInput{Email: email, Password: password}

		userRepoMock.On("FindByEmail", ctx, email).Return(user, nil)

		session, err := service.Login(ctx, input)

		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Equal(t, domain.ErrUserBlocked, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when email is not verified", func(t *testing.T) {
		service, userRepoMock, verificationRepoMock, emailNotificationMock, _ := setupAuthService(t)
		ctx := context.Background()
		email := "unverified@example.com"
		password := "password123"
		passwordHash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		user := &domain.User{
			ID:               uuid.New(),
			Email:            email,
			Name:             "John",
			PasswordHash:     string(passwordHash),
			EmailConfirmedAt: sql.NullTime{Valid: false},
		}
		input := model.LoginInput{Email: email, Password: password}

		userRepoMock.On("FindByEmail", ctx, email).Return(user, nil)
		verificationRepoMock.On("FindValidByUserIDAndFlow", ctx, user.ID, domain.VerificationEmailFlow).Return(nil, repository.ErrVerificationNotFound)
		verificationRepoMock.On("InvalidateByUserIDAndFlow", ctx, user.ID, domain.VerificationEmailFlow).Return(nil)
		verificationRepoMock.On("Create", ctx, mock.AnythingOfType("*domain.Verification")).Return(nil)
		emailNotificationMock.On("SendWelcomeEmail", mock.Anything, mock.Anything, user.Name, mock.Anything, user.Email).Return(nil).Maybe()

		session, err := service.Login(ctx, input)

		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Equal(t, domain.ErrEmailNotVerified, err)
		userRepoMock.AssertExpectations(t)
	})
}

func TestAuthService_UpdatePassword(t *testing.T) {
	t.Run("should update password successfully when current password is correct", func(t *testing.T) {
		service, userRepoMock, _, _, _ := setupAuthService(t)
		ctx := context.Background()
		userID := uuid.New()
		currentPassword := "oldpassword"
		newPassword := "newpassword"
		passwordHash, _ := bcrypt.GenerateFromPassword([]byte(currentPassword), bcrypt.DefaultCost)
		user := &domain.User{
			ID:           userID,
			PasswordHash: string(passwordHash),
		}

		userRepoMock.On("FindByID", ctx, userID).Return(user, nil)
		userRepoMock.On("UpdatePassword", ctx, userID, mock.AnythingOfType("string")).Return(nil)

		err := service.UpdatePassword(ctx, userID, currentPassword, newPassword)

		assert.NoError(t, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when user is not found", func(t *testing.T) {
		service, userRepoMock, _, _, _ := setupAuthService(t)
		ctx := context.Background()
		userID := uuid.New()

		userRepoMock.On("FindByID", ctx, userID).Return(nil, repository.ErrUserNotFound)

		err := service.UpdatePassword(ctx, userID, "oldpassword", "newpassword")

		assert.Error(t, err)
		assert.Equal(t, domain.ErrUserNotFound, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when current password is incorrect", func(t *testing.T) {
		service, userRepoMock, _, _, _ := setupAuthService(t)
		ctx := context.Background()
		userID := uuid.New()
		correctPassword := "correctpassword"
		passwordHash, _ := bcrypt.GenerateFromPassword([]byte(correctPassword), bcrypt.DefaultCost)
		user := &domain.User{
			ID:           userID,
			PasswordHash: string(passwordHash),
		}

		userRepoMock.On("FindByID", ctx, userID).Return(user, nil)

		err := service.UpdatePassword(ctx, userID, "wrongpassword", "newpassword")

		assert.Error(t, err)
		assert.Equal(t, domain.ErrPasswordMismatch, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository fails to update password", func(t *testing.T) {
		service, userRepoMock, _, _, _ := setupAuthService(t)
		ctx := context.Background()
		userID := uuid.New()
		currentPassword := "oldpassword"
		passwordHash, _ := bcrypt.GenerateFromPassword([]byte(currentPassword), bcrypt.DefaultCost)
		user := &domain.User{
			ID:           userID,
			PasswordHash: string(passwordHash),
		}
		repoErr := errors.New("database error")

		userRepoMock.On("FindByID", ctx, userID).Return(user, nil)
		userRepoMock.On("UpdatePassword", ctx, userID, mock.AnythingOfType("string")).Return(repoErr)

		err := service.UpdatePassword(ctx, userID, currentPassword, "newpassword")

		assert.Error(t, err)
		userRepoMock.AssertExpectations(t)
	})
}

func TestAuthService_ChangeEmail(t *testing.T) {
	t.Run("should change email successfully when token is valid", func(t *testing.T) {
		service, userRepoMock, verificationRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		userID := uuid.New()
		token := "valid-token"
		newEmail := "newemail@example.com"
		verification := &domain.Verification{
			ID:        uuid.New(),
			Token:     token,
			UserID:    userID,
			Flow:      domain.ChangeEmailFlow,
			ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
			Payload:   sql.NullString{String: newEmail, Valid: true},
		}

		verificationRepoMock.On("FindByToken", ctx, token).Return(verification, nil)
		userRepoMock.On("UpdateEmail", ctx, userID, newEmail).Return(nil)
		verificationRepoMock.On("Delete", ctx, verification.ID).Return(nil)

		err := service.ChangeEmail(ctx, token)

		assert.NoError(t, err)
		verificationRepoMock.AssertExpectations(t)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when verification is not found", func(t *testing.T) {
		service, _, verificationRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		token := "invalid-token"

		verificationRepoMock.On("FindByToken", ctx, token).Return(nil, repository.ErrVerificationNotFound)

		err := service.ChangeEmail(ctx, token)

		assert.Error(t, err)
		assert.Equal(t, domain.ErrVerificationNotFound, err)
		verificationRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when verification is expired", func(t *testing.T) {
		service, _, verificationRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		token := "expired-token"
		verification := &domain.Verification{
			ID:        uuid.New(),
			Token:     token,
			UserID:    uuid.New(),
			Flow:      domain.ChangeEmailFlow,
			ExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
		}

		verificationRepoMock.On("FindByToken", ctx, token).Return(verification, nil)

		err := service.ChangeEmail(ctx, token)

		assert.Error(t, err)
		assert.Equal(t, domain.ErrInvalidVerification, err)
		verificationRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when verification flow is incorrect", func(t *testing.T) {
		service, _, verificationRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		token := "wrong-flow-token"
		verification := &domain.Verification{
			ID:        uuid.New(),
			Token:     token,
			UserID:    uuid.New(),
			Flow:      domain.VerificationEmailFlow,
			ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
		}

		verificationRepoMock.On("FindByToken", ctx, token).Return(verification, nil)

		err := service.ChangeEmail(ctx, token)

		assert.Error(t, err)
		assert.Equal(t, domain.ErrInvalidVerification, err)
		verificationRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when payload is invalid", func(t *testing.T) {
		service, _, verificationRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		token := "valid-token"
		verification := &domain.Verification{
			ID:        uuid.New(),
			Token:     token,
			UserID:    uuid.New(),
			Flow:      domain.ChangeEmailFlow,
			ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
			Payload:   sql.NullString{Valid: false},
		}

		verificationRepoMock.On("FindByToken", ctx, token).Return(verification, nil)

		err := service.ChangeEmail(ctx, token)

		assert.Error(t, err)
		assert.Equal(t, domain.ErrInvalidVerificationPayload, err)
		verificationRepoMock.AssertExpectations(t)
	})
}

func TestAuthService_RequestPasswordReset(t *testing.T) {
	t.Run("should request password reset successfully when user exists", func(t *testing.T) {
		service, userRepoMock, verificationRepoMock, emailNotificationMock, _ := setupAuthService(t)
		ctx := context.Background()
		email := "john@example.com"
		user := &domain.User{
			ID:    uuid.New(),
			Email: email,
			Name:  "John Doe",
		}

		userRepoMock.On("FindByEmail", ctx, email).Return(user, nil)
		verificationRepoMock.On("Create", ctx, mock.AnythingOfType("*domain.Verification")).Return(nil)
		emailNotificationMock.On("SendResetPasswordEmail", mock.Anything, user.Name, mock.Anything, email).Return(nil).Maybe()

		err := service.RequestPasswordReset(ctx, email)

		assert.NoError(t, err)
		userRepoMock.AssertExpectations(t)
		verificationRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when user is not found", func(t *testing.T) {
		service, userRepoMock, _, _, _ := setupAuthService(t)
		ctx := context.Background()
		email := "nonexistent@example.com"

		userRepoMock.On("FindByEmail", ctx, email).Return(nil, repository.ErrUserNotFound)

		err := service.RequestPasswordReset(ctx, email)

		assert.Error(t, err)
		assert.Equal(t, domain.ErrUserNotFound, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository fails to create verification", func(t *testing.T) {
		service, userRepoMock, verificationRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		email := "john@example.com"
		user := &domain.User{
			ID:    uuid.New(),
			Email: email,
			Name:  "John Doe",
		}
		repoErr := errors.New("database error")

		userRepoMock.On("FindByEmail", ctx, email).Return(user, nil)
		verificationRepoMock.On("Create", ctx, mock.AnythingOfType("*domain.Verification")).Return(repoErr)

		err := service.RequestPasswordReset(ctx, email)

		assert.Error(t, err)
		userRepoMock.AssertExpectations(t)
		verificationRepoMock.AssertExpectations(t)
	})
}

func TestAuthService_ResetPassword(t *testing.T) {
	t.Run("should reset password successfully when token is valid", func(t *testing.T) {
		service, userRepoMock, verificationRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		userID := uuid.New()
		token := "valid-token"
		newPassword := "newpassword123"
		verification := &domain.Verification{
			ID:        uuid.New(),
			Token:     token,
			UserID:    userID,
			Flow:      domain.ResetPasswordFlow,
			ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
		}

		verificationRepoMock.On("FindByToken", ctx, token).Return(verification, nil)
		userRepoMock.On("UpdatePassword", ctx, userID, mock.AnythingOfType("string")).Return(nil)
		verificationRepoMock.On("Delete", ctx, verification.ID).Return(nil)

		session, err := service.ResetPassword(ctx, token, newPassword)

		assert.NoError(t, err)
		assert.Nil(t, session)
		verificationRepoMock.AssertExpectations(t)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when verification is not found", func(t *testing.T) {
		service, _, verificationRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		token := "invalid-token"

		verificationRepoMock.On("FindByToken", ctx, token).Return(nil, repository.ErrVerificationNotFound)

		session, err := service.ResetPassword(ctx, token, "newpassword")

		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Equal(t, domain.ErrVerificationNotFound, err)
		verificationRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when verification is expired", func(t *testing.T) {
		service, _, verificationRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		token := "expired-token"
		verification := &domain.Verification{
			ID:        uuid.New(),
			Token:     token,
			UserID:    uuid.New(),
			Flow:      domain.ResetPasswordFlow,
			ExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
		}

		verificationRepoMock.On("FindByToken", ctx, token).Return(verification, nil)

		session, err := service.ResetPassword(ctx, token, "newpassword")

		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Equal(t, domain.ErrInvalidVerification, err)
		verificationRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when verification flow is incorrect", func(t *testing.T) {
		service, _, verificationRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		token := "wrong-flow-token"
		verification := &domain.Verification{
			ID:        uuid.New(),
			Token:     token,
			UserID:    uuid.New(),
			Flow:      domain.VerificationEmailFlow,
			ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
		}

		verificationRepoMock.On("FindByToken", ctx, token).Return(verification, nil)

		session, err := service.ResetPassword(ctx, token, "newpassword")

		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Equal(t, domain.ErrInvalidVerification, err)
		verificationRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository fails to update password", func(t *testing.T) {
		service, userRepoMock, verificationRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		userID := uuid.New()
		token := "valid-token"
		verification := &domain.Verification{
			ID:        uuid.New(),
			Token:     token,
			UserID:    userID,
			Flow:      domain.ResetPasswordFlow,
			ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
		}
		repoErr := errors.New("database error")

		verificationRepoMock.On("FindByToken", ctx, token).Return(verification, nil)
		userRepoMock.On("UpdatePassword", ctx, userID, mock.AnythingOfType("string")).Return(repoErr)

		session, err := service.ResetPassword(ctx, token, "newpassword")

		assert.Error(t, err)
		assert.Nil(t, session)
		verificationRepoMock.AssertExpectations(t)
		userRepoMock.AssertExpectations(t)
	})
}
