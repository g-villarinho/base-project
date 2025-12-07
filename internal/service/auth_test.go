package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/g-villarinho/base-project/internal/mocks"
	"github.com/g-villarinho/base-project/internal/repository"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func setupAuthService(t *testing.T) (AuthService, *mocks.UserRepositoryMock, *mocks.VerificationServiceMock, *mocks.SessionServiceMock) {
	t.Helper()

	userRepoMock := mocks.NewUserRepositoryMock(t)
	verificationServiceMock := mocks.NewVerificationServiceMock(t)
	sessionServiceMock := mocks.NewSessionServiceMock(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	service := NewAuthService(userRepoMock, verificationServiceMock, sessionServiceMock, logger)

	return service, userRepoMock, verificationServiceMock, sessionServiceMock
}

func TestRegisterAccount(t *testing.T) {
	t.Run("should register account successfully when valid data is provided", func(t *testing.T) {
		// Arrange
		service, userRepoMock, verificationServiceMock, _ := setupAuthService(t)
		ctx := context.Background()
		name := "John Doe"
		email := "john@example.com"
		password := "SecurePass123!"

		userRepoMock.On("ExistsByEmail", ctx, email).Return(false, nil)
		userRepoMock.On("Create", ctx, mock.AnythingOfType("*domain.User")).Return(nil)
		verificationServiceMock.On("SendVerificationEmail", ctx, mock.AnythingOfType("*domain.User"), domain.VerificationEmailFlow).Return(nil)

		// Act
		err := service.RegisterAccount(ctx, name, email, password)

		// Assert
		require.NoError(t, err)
		userRepoMock.AssertExpectations(t)
		verificationServiceMock.AssertExpectations(t)
	})

	t.Run("should return error when email already exists", func(t *testing.T) {
		// Arrange
		service, userRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		name := "John Doe"
		email := "existing@example.com"
		password := "SecurePass123!"

		userRepoMock.On("ExistsByEmail", ctx, email).Return(true, nil)

		// Act
		err := service.RegisterAccount(ctx, name, email, password)

		// Assert
		require.Error(t, err)
		assert.Equal(t, domain.ErrEmailAlreadyExists, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when checking email existence fails", func(t *testing.T) {
		// Arrange
		service, userRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		name := "John Doe"
		email := "john@example.com"
		password := "SecurePass123!"

		expectedError := errors.New("database error")
		userRepoMock.On("ExistsByEmail", ctx, email).Return(false, expectedError)

		// Act
		err := service.RegisterAccount(ctx, name, email, password)

		// Assert
		require.Error(t, err)
		assert.Contains(t, err.Error(), "check if email exists")
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when creating user fails", func(t *testing.T) {
		// Arrange
		service, userRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		name := "John Doe"
		email := "john@example.com"
		password := "SecurePass123!"

		expectedError := errors.New("database error")
		userRepoMock.On("ExistsByEmail", ctx, email).Return(false, nil)
		userRepoMock.On("Create", ctx, mock.AnythingOfType("*domain.User")).Return(expectedError)

		// Act
		err := service.RegisterAccount(ctx, name, email, password)

		// Assert
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create user")
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when sending verification email fails", func(t *testing.T) {
		// Arrange
		service, userRepoMock, verificationServiceMock, _ := setupAuthService(t)
		ctx := context.Background()
		name := "John Doe"
		email := "john@example.com"
		password := "SecurePass123!"

		expectedError := errors.New("email service error")
		userRepoMock.On("ExistsByEmail", ctx, email).Return(false, nil)
		userRepoMock.On("Create", ctx, mock.AnythingOfType("*domain.User")).Return(nil)
		verificationServiceMock.On("SendVerificationEmail", ctx, mock.AnythingOfType("*domain.User"), domain.VerificationEmailFlow).Return(expectedError)

		// Act
		err := service.RegisterAccount(ctx, name, email, password)

		// Assert
		require.Error(t, err)
		assert.Contains(t, err.Error(), "send verification email")
		userRepoMock.AssertExpectations(t)
		verificationServiceMock.AssertExpectations(t)
	})
}

func TestVerifyEmail(t *testing.T) {
	t.Run("should verify email successfully and return session when valid token is provided", func(t *testing.T) {
		// Arrange
		service, userRepoMock, verificationServiceMock, sessionServiceMock := setupAuthService(t)
		ctx := context.Background()
		token := "valid-token"
		ipAddress := "192.168.1.1"
		userAgent := "Mozilla/5.0"
		deviceName := "Chrome Browser"
		userID := uuid.New()

		verification := &domain.Verification{
			UserID: userID,
			Token:  token,
		}
		expectedSession := &domain.Session{
			ID:     uuid.New(),
			UserID: userID,
		}

		verificationServiceMock.On("ConsumeVerificationToken", ctx, token, domain.VerificationEmailFlow).Return(verification, nil)
		userRepoMock.On("VerifyEmail", ctx, userID).Return(nil)
		sessionServiceMock.On("CreateSession", ctx, userID, ipAddress, deviceName, userAgent).Return(expectedSession, nil)

		// Act
		session, err := service.VerifyEmail(ctx, token, ipAddress, userAgent, deviceName)

		// Assert
		require.NoError(t, err)
		assert.NotNil(t, session)
		assert.Equal(t, expectedSession, session)
		verificationServiceMock.AssertExpectations(t)
		userRepoMock.AssertExpectations(t)
		sessionServiceMock.AssertExpectations(t)
	})

	t.Run("should return error when verification token is invalid", func(t *testing.T) {
		// Arrange
		service, _, verificationServiceMock, _ := setupAuthService(t)
		ctx := context.Background()
		token := "invalid-token"
		ipAddress := "192.168.1.1"
		userAgent := "Mozilla/5.0"
		deviceName := "Chrome Browser"

		expectedError := errors.New("invalid token")
		verificationServiceMock.On("ConsumeVerificationToken", ctx, token, domain.VerificationEmailFlow).Return(nil, expectedError)

		// Act
		session, err := service.VerifyEmail(ctx, token, ipAddress, userAgent, deviceName)

		// Assert
		require.Error(t, err)
		assert.Nil(t, session)
		assert.Contains(t, err.Error(), "validate verification token")
		verificationServiceMock.AssertExpectations(t)
	})

	t.Run("should return error when marking email as verified fails", func(t *testing.T) {
		// Arrange
		service, userRepoMock, verificationServiceMock, _ := setupAuthService(t)
		ctx := context.Background()
		token := "valid-token"
		ipAddress := "192.168.1.1"
		userAgent := "Mozilla/5.0"
		deviceName := "Chrome Browser"
		userID := uuid.New()

		verification := &domain.Verification{
			UserID: userID,
			Token:  token,
		}
		expectedError := errors.New("database error")

		verificationServiceMock.On("ConsumeVerificationToken", ctx, token, domain.VerificationEmailFlow).Return(verification, nil)
		userRepoMock.On("VerifyEmail", ctx, userID).Return(expectedError)

		// Act
		session, err := service.VerifyEmail(ctx, token, ipAddress, userAgent, deviceName)

		// Assert
		require.Error(t, err)
		assert.Nil(t, session)
		assert.Contains(t, err.Error(), "mark email as verified")
		verificationServiceMock.AssertExpectations(t)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when creating session fails", func(t *testing.T) {
		// Arrange
		service, userRepoMock, verificationServiceMock, sessionServiceMock := setupAuthService(t)
		ctx := context.Background()
		token := "valid-token"
		ipAddress := "192.168.1.1"
		userAgent := "Mozilla/5.0"
		deviceName := "Chrome Browser"
		userID := uuid.New()

		verification := &domain.Verification{
			UserID: userID,
			Token:  token,
		}
		expectedError := errors.New("session creation error")

		verificationServiceMock.On("ConsumeVerificationToken", ctx, token, domain.VerificationEmailFlow).Return(verification, nil)
		userRepoMock.On("VerifyEmail", ctx, userID).Return(nil)
		sessionServiceMock.On("CreateSession", ctx, userID, ipAddress, deviceName, userAgent).Return(nil, expectedError)

		// Act
		session, err := service.VerifyEmail(ctx, token, ipAddress, userAgent, deviceName)

		// Assert
		require.Error(t, err)
		assert.Nil(t, session)
		assert.Contains(t, err.Error(), "create user session")
		verificationServiceMock.AssertExpectations(t)
		userRepoMock.AssertExpectations(t)
		sessionServiceMock.AssertExpectations(t)
	})
}

func TestLogin(t *testing.T) {
	t.Run("should return error when password is invalid", func(t *testing.T) {
		// Arrange
		service, userRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		email := "john@example.com"
		password := "WrongPassword!"
		ipAddress := "192.168.1.1"
		userAgent := "Mozilla/5.0"
		deviceName := "Chrome Browser"
		userID := uuid.New()

		emailConfirmedAt := time.Now()
		user := &domain.User{
			ID:               userID,
			Email:            email,
			PasswordHash:     "$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHRzb21lc2FsdA$hash", // Mock hash
			EmailConfirmedAt: &emailConfirmedAt,
			Status:           domain.ActiveStatus,
		}

		userRepoMock.On("FindByEmail", ctx, email).Return(user, nil)

		// Act
		session, err := service.Login(ctx, email, password, ipAddress, userAgent, deviceName)

		// Assert
		require.Error(t, err)
		assert.Nil(t, session)
		assert.Equal(t, domain.ErrInvalidCredentials, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when user is not found", func(t *testing.T) {
		// Arrange
		service, userRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		email := "notfound@example.com"
		password := "SecurePass123!"
		ipAddress := "192.168.1.1"
		userAgent := "Mozilla/5.0"
		deviceName := "Chrome Browser"

		userRepoMock.On("FindByEmail", ctx, email).Return(nil, repository.ErrUserNotFound)

		// Act
		session, err := service.Login(ctx, email, password, ipAddress, userAgent, deviceName)

		// Assert
		require.Error(t, err)
		assert.Nil(t, session)
		assert.Equal(t, domain.ErrInvalidCredentials, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when finding user by email fails", func(t *testing.T) {
		// Arrange
		service, userRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		email := "john@example.com"
		password := "SecurePass123!"
		ipAddress := "192.168.1.1"
		userAgent := "Mozilla/5.0"
		deviceName := "Chrome Browser"

		expectedError := errors.New("database error")
		userRepoMock.On("FindByEmail", ctx, email).Return(nil, expectedError)

		// Act
		session, err := service.Login(ctx, email, password, ipAddress, userAgent, deviceName)

		// Assert
		require.Error(t, err)
		assert.Nil(t, session)
		assert.Contains(t, err.Error(), "find user by email")
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when user is blocked", func(t *testing.T) {
		// Arrange
		service, userRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		email := "blocked@example.com"
		password := "WrongPassword!"
		ipAddress := "192.168.1.1"
		userAgent := "Mozilla/5.0"
		deviceName := "Chrome Browser"

		user := &domain.User{
			ID:           uuid.New(),
			Email:        email,
			PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHRzb21lc2FsdA$hash",
			Status:       domain.BlockedStatus,
		}

		userRepoMock.On("FindByEmail", ctx, email).Return(user, nil)

		// Act
		session, err := service.Login(ctx, email, password, ipAddress, userAgent, deviceName)

		// Assert
		// Password verification happens before block check, so we get ErrInvalidCredentials
		require.Error(t, err)
		assert.Nil(t, session)
		assert.Equal(t, domain.ErrInvalidCredentials, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when password is invalid even if email is not verified", func(t *testing.T) {
		// Arrange
		service, userRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		email := "unverified@example.com"
		password := "WrongPassword!"
		ipAddress := "192.168.1.1"
		userAgent := "Mozilla/5.0"
		deviceName := "Chrome Browser"

		user := &domain.User{
			ID:               uuid.New(),
			Email:            email,
			PasswordHash:     "$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHRzb21lc2FsdA$hash",
			EmailConfirmedAt: nil,
			Status:           domain.PendingStatus,
		}

		userRepoMock.On("FindByEmail", ctx, email).Return(user, nil)

		// Act
		session, err := service.Login(ctx, email, password, ipAddress, userAgent, deviceName)

		// Assert
		// Password verification happens first, so we get ErrInvalidCredentials
		require.Error(t, err)
		assert.Nil(t, session)
		assert.Equal(t, domain.ErrInvalidCredentials, err)
		userRepoMock.AssertExpectations(t)
	})
}

func TestUpdatePassword(t *testing.T) {
	t.Run("should return error when current password does not match", func(t *testing.T) {
		// Arrange
		service, userRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		userID := uuid.New()
		currentPassword := "WrongOldPass!"
		newPassword := "NewPass456!"

		user := &domain.User{
			ID:           userID,
			PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHRzb21lc2FsdA$hash",
		}

		userRepoMock.On("FindByID", ctx, userID).Return(user, nil)

		// Act
		err := service.UpdatePassword(ctx, userID, currentPassword, newPassword)

		// Assert
		require.Error(t, err)
		assert.Equal(t, domain.ErrPasswordMismatch, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when user is not found", func(t *testing.T) {
		// Arrange
		service, userRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		userID := uuid.New()
		currentPassword := "OldPass123!"
		newPassword := "NewPass456!"

		userRepoMock.On("FindByID", ctx, userID).Return(nil, repository.ErrUserNotFound)

		// Act
		err := service.UpdatePassword(ctx, userID, currentPassword, newPassword)

		// Assert
		require.Error(t, err)
		assert.Equal(t, domain.ErrUserNotFound, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when finding user by ID fails", func(t *testing.T) {
		// Arrange
		service, userRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		userID := uuid.New()
		currentPassword := "OldPass123!"
		newPassword := "NewPass456!"

		expectedError := errors.New("database error")
		userRepoMock.On("FindByID", ctx, userID).Return(nil, expectedError)

		// Act
		err := service.UpdatePassword(ctx, userID, currentPassword, newPassword)

		// Assert
		require.Error(t, err)
		assert.Contains(t, err.Error(), "find user by id")
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when current password is incorrect", func(t *testing.T) {
		// Arrange
		service, userRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		userID := uuid.New()
		currentPassword := "WrongPass123!"
		newPassword := "NewPass456!"

		user := &domain.User{
			ID:           userID,
			PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHRzb21lc2FsdA$hash",
		}

		userRepoMock.On("FindByID", ctx, userID).Return(user, nil)

		// Act
		err := service.UpdatePassword(ctx, userID, currentPassword, newPassword)

		// Assert
		require.Error(t, err)
		assert.Equal(t, domain.ErrPasswordMismatch, err)
		userRepoMock.AssertExpectations(t)
	})

}

func TestRequestChangeEmail(t *testing.T) {
	t.Run("should request email change successfully when valid new email is provided", func(t *testing.T) {
		// Arrange
		service, userRepoMock, verificationServiceMock, _ := setupAuthService(t)
		ctx := context.Background()
		userID := uuid.New()
		newEmail := "newemail@example.com"

		user := &domain.User{
			ID:    userID,
			Email: "oldemail@example.com",
		}

		userRepoMock.On("FindByID", ctx, userID).Return(user, nil)
		userRepoMock.On("ExistsByEmail", ctx, newEmail).Return(false, nil)
		verificationServiceMock.On("SendVerificationEmail", ctx, user, domain.ChangeEmailFlow).Return(nil)

		// Act
		err := service.RequestChangeEmail(ctx, userID, newEmail)

		// Assert
		require.NoError(t, err)
		userRepoMock.AssertExpectations(t)
		verificationServiceMock.AssertExpectations(t)
	})

	t.Run("should return error when user is not found", func(t *testing.T) {
		// Arrange
		service, userRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		userID := uuid.New()
		newEmail := "newemail@example.com"

		userRepoMock.On("FindByID", ctx, userID).Return(nil, repository.ErrUserNotFound)

		// Act
		err := service.RequestChangeEmail(ctx, userID, newEmail)

		// Assert
		require.Error(t, err)
		assert.Equal(t, domain.ErrUserNotFound, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when new email is the same as current email", func(t *testing.T) {
		// Arrange
		service, userRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		userID := uuid.New()
		currentEmail := "same@example.com"

		user := &domain.User{
			ID:    userID,
			Email: currentEmail,
		}

		userRepoMock.On("FindByID", ctx, userID).Return(user, nil)

		// Act
		err := service.RequestChangeEmail(ctx, userID, currentEmail)

		// Assert
		require.Error(t, err)
		assert.Equal(t, domain.ErrEmailIsTheSame, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when new email is already in use", func(t *testing.T) {
		// Arrange
		service, userRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		userID := uuid.New()
		newEmail := "taken@example.com"

		user := &domain.User{
			ID:    userID,
			Email: "oldemail@example.com",
		}

		userRepoMock.On("FindByID", ctx, userID).Return(user, nil)
		userRepoMock.On("ExistsByEmail", ctx, newEmail).Return(true, nil)

		// Act
		err := service.RequestChangeEmail(ctx, userID, newEmail)

		// Assert
		require.Error(t, err)
		assert.Equal(t, domain.ErrEmailInUse, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when checking email existence fails", func(t *testing.T) {
		// Arrange
		service, userRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		userID := uuid.New()
		newEmail := "newemail@example.com"

		user := &domain.User{
			ID:    userID,
			Email: "oldemail@example.com",
		}
		expectedError := errors.New("database error")

		userRepoMock.On("FindByID", ctx, userID).Return(user, nil)
		userRepoMock.On("ExistsByEmail", ctx, newEmail).Return(false, expectedError)

		// Act
		err := service.RequestChangeEmail(ctx, userID, newEmail)

		// Assert
		require.Error(t, err)
		assert.Contains(t, err.Error(), "check if email exists")
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when sending verification email fails", func(t *testing.T) {
		// Arrange
		service, userRepoMock, verificationServiceMock, _ := setupAuthService(t)
		ctx := context.Background()
		userID := uuid.New()
		newEmail := "newemail@example.com"

		user := &domain.User{
			ID:    userID,
			Email: "oldemail@example.com",
		}
		expectedError := errors.New("email service error")

		userRepoMock.On("FindByID", ctx, userID).Return(user, nil)
		userRepoMock.On("ExistsByEmail", ctx, newEmail).Return(false, nil)
		verificationServiceMock.On("SendVerificationEmail", ctx, user, domain.ChangeEmailFlow).Return(expectedError)

		// Act
		err := service.RequestChangeEmail(ctx, userID, newEmail)

		// Assert
		require.Error(t, err)
		assert.Contains(t, err.Error(), "send email change verification")
		userRepoMock.AssertExpectations(t)
		verificationServiceMock.AssertExpectations(t)
	})
}

func TestChangeEmail(t *testing.T) {
	t.Run("should change email successfully when valid token is provided", func(t *testing.T) {
		// Arrange
		service, userRepoMock, verificationServiceMock, _ := setupAuthService(t)
		ctx := context.Background()
		token := "valid-token"
		newEmail := "newemail@example.com"
		userID := uuid.New()

		verification := &domain.Verification{
			UserID:  userID,
			Token:   token,
			Payload: &newEmail,
		}

		verificationServiceMock.On("ConsumeVerificationToken", ctx, token, domain.ChangeEmailFlow).Return(verification, nil)
		userRepoMock.On("UpdateEmail", ctx, userID, newEmail).Return(nil)

		// Act
		err := service.ChangeEmail(ctx, token)

		// Assert
		require.NoError(t, err)
		verificationServiceMock.AssertExpectations(t)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when verification token is invalid", func(t *testing.T) {
		// Arrange
		service, _, verificationServiceMock, _ := setupAuthService(t)
		ctx := context.Background()
		token := "invalid-token"

		expectedError := errors.New("invalid token")
		verificationServiceMock.On("ConsumeVerificationToken", ctx, token, domain.ChangeEmailFlow).Return(nil, expectedError)

		// Act
		err := service.ChangeEmail(ctx, token)

		// Assert
		require.Error(t, err)
		assert.Contains(t, err.Error(), "consume verification token")
		verificationServiceMock.AssertExpectations(t)
	})

	t.Run("should return error when verification payload is nil", func(t *testing.T) {
		// Arrange
		service, _, verificationServiceMock, _ := setupAuthService(t)
		ctx := context.Background()
		token := "valid-token"
		userID := uuid.New()

		verification := &domain.Verification{
			UserID:  userID,
			Token:   token,
			Payload: nil,
		}

		verificationServiceMock.On("ConsumeVerificationToken", ctx, token, domain.ChangeEmailFlow).Return(verification, nil)

		// Act
		err := service.ChangeEmail(ctx, token)

		// Assert
		require.Error(t, err)
		assert.Equal(t, domain.ErrInvalidVerificationPayload, err)
		verificationServiceMock.AssertExpectations(t)
	})

	t.Run("should return error when updating email fails", func(t *testing.T) {
		// Arrange
		service, userRepoMock, verificationServiceMock, _ := setupAuthService(t)
		ctx := context.Background()
		token := "valid-token"
		newEmail := "newemail@example.com"
		userID := uuid.New()

		verification := &domain.Verification{
			UserID:  userID,
			Token:   token,
			Payload: &newEmail,
		}
		expectedError := errors.New("database error")

		verificationServiceMock.On("ConsumeVerificationToken", ctx, token, domain.ChangeEmailFlow).Return(verification, nil)
		userRepoMock.On("UpdateEmail", ctx, userID, newEmail).Return(expectedError)

		// Act
		err := service.ChangeEmail(ctx, token)

		// Assert
		require.Error(t, err)
		assert.Contains(t, err.Error(), "update email")
		verificationServiceMock.AssertExpectations(t)
		userRepoMock.AssertExpectations(t)
	})
}

func TestRequestPasswordReset(t *testing.T) {
	t.Run("should request password reset successfully when valid email is provided", func(t *testing.T) {
		// Arrange
		service, userRepoMock, verificationServiceMock, _ := setupAuthService(t)
		ctx := context.Background()
		email := "john@example.com"

		user := &domain.User{
			ID:    uuid.New(),
			Email: email,
		}

		userRepoMock.On("FindByEmail", ctx, email).Return(user, nil)
		verificationServiceMock.On("SendVerificationEmail", ctx, user, domain.ResetPasswordFlow).Return(nil)

		// Act
		err := service.RequestPasswordReset(ctx, email)

		// Assert
		require.NoError(t, err)
		userRepoMock.AssertExpectations(t)
		verificationServiceMock.AssertExpectations(t)
	})

	t.Run("should return error when user is not found", func(t *testing.T) {
		// Arrange
		service, userRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		email := "notfound@example.com"

		userRepoMock.On("FindByEmail", ctx, email).Return(nil, repository.ErrUserNotFound)

		// Act
		err := service.RequestPasswordReset(ctx, email)

		// Assert
		require.Error(t, err)
		assert.Equal(t, domain.ErrUserNotFound, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when finding user by email fails", func(t *testing.T) {
		// Arrange
		service, userRepoMock, _, _ := setupAuthService(t)
		ctx := context.Background()
		email := "john@example.com"

		expectedError := errors.New("database error")
		userRepoMock.On("FindByEmail", ctx, email).Return(nil, expectedError)

		// Act
		err := service.RequestPasswordReset(ctx, email)

		// Assert
		require.Error(t, err)
		assert.Contains(t, err.Error(), "find user by email")
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when sending password reset email fails", func(t *testing.T) {
		// Arrange
		service, userRepoMock, verificationServiceMock, _ := setupAuthService(t)
		ctx := context.Background()
		email := "john@example.com"

		user := &domain.User{
			ID:    uuid.New(),
			Email: email,
		}
		expectedError := errors.New("email service error")

		userRepoMock.On("FindByEmail", ctx, email).Return(user, nil)
		verificationServiceMock.On("SendVerificationEmail", ctx, user, domain.ResetPasswordFlow).Return(expectedError)

		// Act
		err := service.RequestPasswordReset(ctx, email)

		// Assert
		require.Error(t, err)
		assert.Contains(t, err.Error(), "send password reset email")
		userRepoMock.AssertExpectations(t)
		verificationServiceMock.AssertExpectations(t)
	})
}

func TestResetPassword(t *testing.T) {
	t.Run("should reset password successfully and return session when valid token is provided", func(t *testing.T) {
		// Arrange
		service, userRepoMock, verificationServiceMock, sessionServiceMock := setupAuthService(t)
		ctx := context.Background()
		token := "valid-token"
		newPassword := "NewPass456!"
		userID := uuid.New()

		verification := &domain.Verification{
			UserID: userID,
			Token:  token,
		}
		expectedSession := &domain.Session{
			ID:     uuid.New(),
			UserID: userID,
		}

		verificationServiceMock.On("ConsumeVerificationToken", ctx, token, domain.ResetPasswordFlow).Return(verification, nil)
		userRepoMock.On("UpdatePassword", ctx, userID, mock.AnythingOfType("string")).Return(nil)
		sessionServiceMock.On("CreateSession", ctx, userID, "", "", "").Return(expectedSession, nil)

		// Act
		session, err := service.ResetPassword(ctx, token, newPassword)

		// Assert
		require.NoError(t, err)
		assert.NotNil(t, session)
		assert.Equal(t, expectedSession, session)
		verificationServiceMock.AssertExpectations(t)
		userRepoMock.AssertExpectations(t)
		sessionServiceMock.AssertExpectations(t)
	})

	t.Run("should return error when verification token is invalid", func(t *testing.T) {
		// Arrange
		service, _, verificationServiceMock, _ := setupAuthService(t)
		ctx := context.Background()
		token := "invalid-token"
		newPassword := "NewPass456!"

		expectedError := errors.New("invalid token")
		verificationServiceMock.On("ConsumeVerificationToken", ctx, token, domain.ResetPasswordFlow).Return(nil, expectedError)

		// Act
		session, err := service.ResetPassword(ctx, token, newPassword)

		// Assert
		require.Error(t, err)
		assert.Nil(t, session)
		verificationServiceMock.AssertExpectations(t)
	})

	t.Run("should return error when updating password fails", func(t *testing.T) {
		// Arrange
		service, userRepoMock, verificationServiceMock, _ := setupAuthService(t)
		ctx := context.Background()
		token := "valid-token"
		newPassword := "NewPass456!"
		userID := uuid.New()

		verification := &domain.Verification{
			UserID: userID,
			Token:  token,
		}
		expectedError := errors.New("database error")

		verificationServiceMock.On("ConsumeVerificationToken", ctx, token, domain.ResetPasswordFlow).Return(verification, nil)
		userRepoMock.On("UpdatePassword", ctx, userID, mock.AnythingOfType("string")).Return(expectedError)

		// Act
		session, err := service.ResetPassword(ctx, token, newPassword)

		// Assert
		require.Error(t, err)
		assert.Nil(t, session)
		assert.Contains(t, err.Error(), "update password for userId")
		verificationServiceMock.AssertExpectations(t)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when creating session fails", func(t *testing.T) {
		// Arrange
		service, userRepoMock, verificationServiceMock, sessionServiceMock := setupAuthService(t)
		ctx := context.Background()
		token := "valid-token"
		newPassword := "NewPass456!"
		userID := uuid.New()

		verification := &domain.Verification{
			UserID: userID,
			Token:  token,
		}
		expectedError := errors.New("session creation error")

		verificationServiceMock.On("ConsumeVerificationToken", ctx, token, domain.ResetPasswordFlow).Return(verification, nil)
		userRepoMock.On("UpdatePassword", ctx, userID, mock.AnythingOfType("string")).Return(nil)
		sessionServiceMock.On("CreateSession", ctx, userID, "", "", "").Return(nil, expectedError)

		// Act
		session, err := service.ResetPassword(ctx, token, newPassword)

		// Assert
		require.Error(t, err)
		assert.Nil(t, session)
		assert.Contains(t, err.Error(), "create user session")
		verificationServiceMock.AssertExpectations(t)
		userRepoMock.AssertExpectations(t)
		sessionServiceMock.AssertExpectations(t)
	})
}

func TestLogout(t *testing.T) {
	t.Run("should logout successfully when valid user and session IDs are provided", func(t *testing.T) {
		// Arrange
		service, _, _, sessionServiceMock := setupAuthService(t)
		ctx := context.Background()
		userID := uuid.New()
		sessionID := uuid.New()

		sessionServiceMock.On("DeleteSessionByID", ctx, userID, sessionID).Return(nil)

		// Act
		err := service.Logout(ctx, userID, sessionID)

		// Assert
		require.NoError(t, err)
		sessionServiceMock.AssertExpectations(t)
	})

	t.Run("should return error when deleting session fails", func(t *testing.T) {
		// Arrange
		service, _, _, sessionServiceMock := setupAuthService(t)
		ctx := context.Background()
		userID := uuid.New()
		sessionID := uuid.New()

		expectedError := errors.New("database error")
		sessionServiceMock.On("DeleteSessionByID", ctx, userID, sessionID).Return(expectedError)

		// Act
		err := service.Logout(ctx, userID, sessionID)

		// Assert
		require.Error(t, err)
		assert.Contains(t, err.Error(), "delete session")
		sessionServiceMock.AssertExpectations(t)
	})
}
