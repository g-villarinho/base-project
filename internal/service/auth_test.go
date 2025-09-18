package service_test

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/g-villarinho/user-demo/config"
	"github.com/g-villarinho/user-demo/internal/domain"
	"github.com/g-villarinho/user-demo/internal/mocks"
	"github.com/g-villarinho/user-demo/internal/model"
	"github.com/g-villarinho/user-demo/internal/repository"
	"github.com/g-villarinho/user-demo/internal/service"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthService_RegisterAccount(t *testing.T) {
	t.Run("should register account successfully when valid data is provided", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		mockEmailNotification := mocks.NewEmailNotificationMock(t)
		config := &config.Config{
			URL: config.URL{
				APIBaseURL: "http://localhost:8080",
				APPBaseURL: "http://localhost:3000",
			},
		}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mockEmailNotification,
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		name := "John Doe"
		email := "john@example.com"
		password := "password123"

		mockUserRepo.On("ExistsByEmail", ctx, email).Return(false, nil)
		mockUserRepo.On("Create", ctx, mock.AnythingOfType("*domain.User")).Return(nil)
		mockVerificationTokenRepo.On("Create", ctx, mock.AnythingOfType("*domain.VerificationToken")).Return(nil)
		mockEmailNotification.On("SendWelcomeEmail", mock.Anything, mock.AnythingOfType("time.Time"), name, mock.AnythingOfType("string"), email).Maybe().Return(nil)

		// Act
		err := authService.RegisterAccount(ctx, name, email, password)

		// Assert
		assert.NoError(t, err)
		mockUserRepo.AssertExpectations(t)
		mockVerificationTokenRepo.AssertExpectations(t)
	})

	t.Run("should return error when email already exists", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		name := "John Doe"
		email := "john@example.com"
		password := "password123"

		mockUserRepo.On("ExistsByEmail", ctx, email).Return(true, nil)

		// Act
		err := authService.RegisterAccount(ctx, name, email, password)

		// Assert
		assert.Error(t, err)
		assert.Equal(t, domain.ErrEmailAlreadyExists, err)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error when checking email existence fails", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		name := "John Doe"
		email := "john@example.com"
		password := "password123"

		expectedError := errors.New("database error")
		mockUserRepo.On("ExistsByEmail", ctx, email).Return(false, expectedError)

		// Act
		err := authService.RegisterAccount(ctx, name, email, password)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "find user by email")
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error when user creation fails", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		name := "John Doe"
		email := "john@example.com"
		password := "password123"

		expectedError := errors.New("database error")
		mockUserRepo.On("ExistsByEmail", ctx, email).Return(false, nil)
		mockUserRepo.On("Create", ctx, mock.AnythingOfType("*domain.User")).Return(expectedError)

		// Act
		err := authService.RegisterAccount(ctx, name, email, password)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "create user")
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error when verification token creation fails", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		name := "John Doe"
		email := "john@example.com"
		password := "password123"

		expectedError := errors.New("database error")
		mockUserRepo.On("ExistsByEmail", ctx, email).Return(false, nil)
		mockUserRepo.On("Create", ctx, mock.AnythingOfType("*domain.User")).Return(nil)
		mockVerificationTokenRepo.On("Create", ctx, mock.AnythingOfType("*domain.VerificationToken")).Return(expectedError)

		// Act
		err := authService.RegisterAccount(ctx, name, email, password)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "create verification code")
		mockUserRepo.AssertExpectations(t)
		mockVerificationTokenRepo.AssertExpectations(t)
	})

	t.Run("should create user with correct data", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		mockEmailNotification := mocks.NewEmailNotificationMock(t)
		config := &config.Config{
			URL: config.URL{
				APIBaseURL: "http://localhost:8080",
				APPBaseURL: "http://localhost:3000",
			},
		}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mockEmailNotification,
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		name := "John Doe"
		email := "john@example.com"
		password := "password123"

		mockUserRepo.On("ExistsByEmail", ctx, email).Return(false, nil)
		mockUserRepo.On("Create", ctx, mock.MatchedBy(func(user *domain.User) bool {
			return user.Name == name &&
				user.Email == email &&
				user.Status == domain.PendingStatus &&
				len(user.PasswordHash) > 0 &&
				user.ID != uuid.Nil
		})).Return(nil)
		mockVerificationTokenRepo.On("Create", ctx, mock.MatchedBy(func(token *domain.VerificationToken) bool {
			return token.Flow == domain.VerificationEmailFlow &&
				token.UserID != uuid.Nil &&
				!token.IsExpired()
		})).Return(nil)
		mockEmailNotification.On("SendWelcomeEmail", mock.Anything, mock.AnythingOfType("time.Time"), name, mock.AnythingOfType("string"), email).Maybe().Return(nil)

		// Act
		err := authService.RegisterAccount(ctx, name, email, password)

		// Assert
		assert.NoError(t, err)
		mockUserRepo.AssertExpectations(t)
		mockVerificationTokenRepo.AssertExpectations(t)
	})
}

func TestAuthService_UpdatePassword(t *testing.T) {
	t.Run("should update password successfully when current password is correct", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		userID := uuid.New()
		currentPassword := "oldpassword123"
		newPassword := "newpassword456"

		hashedCurrentPassword, _ := bcrypt.GenerateFromPassword([]byte(currentPassword), bcrypt.DefaultCost)
		user := &domain.User{
			ID:           userID,
			PasswordHash: string(hashedCurrentPassword),
		}

		mockUserRepo.On("FindByID", ctx, userID).Return(user, nil)
		mockUserRepo.On("UpdatePassword", ctx, userID, mock.MatchedBy(func(hashedPassword string) bool {
			// Verify the new password was properly hashed
			err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(newPassword))
			return err == nil
		})).Return(nil)

		// Act
		err := authService.UpdatePassword(ctx, userID, currentPassword, newPassword)

		// Assert
		assert.NoError(t, err)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error when user not found", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		userID := uuid.New()
		currentPassword := "oldpassword123"
		newPassword := "newpassword456"

		mockUserRepo.On("FindByID", ctx, userID).Return(nil, repository.ErrUserNotFound)

		// Act
		err := authService.UpdatePassword(ctx, userID, currentPassword, newPassword)

		// Assert
		assert.Error(t, err)
		assert.Equal(t, domain.ErrUserNotFound, err)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error when current password is incorrect", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		userID := uuid.New()
		currentPassword := "wrongpassword"
		newPassword := "newpassword456"

		hashedCurrentPassword, _ := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)
		user := &domain.User{
			ID:           userID,
			PasswordHash: string(hashedCurrentPassword),
		}

		mockUserRepo.On("FindByID", ctx, userID).Return(user, nil)

		// Act
		err := authService.UpdatePassword(ctx, userID, currentPassword, newPassword)

		// Assert
		assert.Error(t, err)
		assert.Equal(t, domain.ErrPasswordMismatch, err)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error when repository FindByID fails with database error", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		userID := uuid.New()
		currentPassword := "oldpassword123"
		newPassword := "newpassword456"

		expectedError := errors.New("database connection error")
		mockUserRepo.On("FindByID", ctx, userID).Return(nil, expectedError)

		// Act
		err := authService.UpdatePassword(ctx, userID, currentPassword, newPassword)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "find user by id")
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error when password update fails", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		userID := uuid.New()
		currentPassword := "oldpassword123"
		newPassword := "newpassword456"

		hashedCurrentPassword, _ := bcrypt.GenerateFromPassword([]byte(currentPassword), bcrypt.DefaultCost)
		user := &domain.User{
			ID:           userID,
			PasswordHash: string(hashedCurrentPassword),
		}

		expectedError := errors.New("database update error")
		mockUserRepo.On("FindByID", ctx, userID).Return(user, nil)
		mockUserRepo.On("UpdatePassword", ctx, userID, mock.AnythingOfType("string")).Return(expectedError)

		// Act
		err := authService.UpdatePassword(ctx, userID, currentPassword, newPassword)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "update password for userId")
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should handle empty passwords correctly", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		userID := uuid.New()
		currentPassword := ""
		newPassword := "newpassword456"

		hashedCurrentPassword, _ := bcrypt.GenerateFromPassword([]byte("actualpassword"), bcrypt.DefaultCost)
		user := &domain.User{
			ID:           userID,
			PasswordHash: string(hashedCurrentPassword),
		}

		mockUserRepo.On("FindByID", ctx, userID).Return(user, nil)

		// Act
		err := authService.UpdatePassword(ctx, userID, currentPassword, newPassword)

		// Assert
		assert.Error(t, err)
		assert.Equal(t, domain.ErrPasswordMismatch, err)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should allow updating to the same password", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		userID := uuid.New()
		password := "samepassword123"

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		user := &domain.User{
			ID:           userID,
			PasswordHash: string(hashedPassword),
		}

		mockUserRepo.On("FindByID", ctx, userID).Return(user, nil)
		mockUserRepo.On("UpdatePassword", ctx, userID, mock.AnythingOfType("string")).Return(nil)

		// Act
		err := authService.UpdatePassword(ctx, userID, password, password)

		// Assert
		assert.NoError(t, err)
		mockUserRepo.AssertExpectations(t)
	})
}

func TestAuthService_RequestChangeEmail(t *testing.T) {
	t.Run("should request email change successfully when valid data is provided", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{
			URL: config.URL{
				APIBaseURL: "http://localhost:8080",
			},
		}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		userID := uuid.New()
		currentEmail := "current@example.com"
		newEmail := "new@example.com"

		user := &domain.User{
			ID:    userID,
			Email: currentEmail,
		}

		mockUserRepo.On("FindByID", ctx, userID).Return(user, nil)
		mockUserRepo.On("ExistsByEmail", ctx, newEmail).Return(false, nil)
		mockVerificationTokenRepo.On("Create", ctx, mock.MatchedBy(func(token *domain.VerificationToken) bool {
			return token.Flow == domain.ChangeEmailFlow &&
				token.UserID == userID &&
				token.Payload.Valid &&
				token.Payload.String == newEmail &&
				!token.IsExpired()
		})).Return(nil)

		// Act
		err := authService.RequestChangeEmail(ctx, userID, newEmail)

		// Assert
		assert.NoError(t, err)
		mockUserRepo.AssertExpectations(t)
		mockVerificationTokenRepo.AssertExpectations(t)
	})

	t.Run("should return error when user not found", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		userID := uuid.New()
		newEmail := "new@example.com"

		mockUserRepo.On("FindByID", ctx, userID).Return(nil, repository.ErrUserNotFound)

		// Act
		err := authService.RequestChangeEmail(ctx, userID, newEmail)

		// Assert
		assert.Error(t, err)
		assert.Equal(t, domain.ErrUserNotFound, err)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error when new email is the same as current email", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		userID := uuid.New()
		email := "same@example.com"

		user := &domain.User{
			ID:    userID,
			Email: email,
		}

		mockUserRepo.On("FindByID", ctx, userID).Return(user, nil)

		// Act
		err := authService.RequestChangeEmail(ctx, userID, email)

		// Assert
		assert.Error(t, err)
		assert.Equal(t, domain.ErrEmailIsTheSame, err)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error when new email is already in use", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		userID := uuid.New()
		currentEmail := "current@example.com"
		newEmail := "existing@example.com"

		user := &domain.User{
			ID:    userID,
			Email: currentEmail,
		}

		mockUserRepo.On("FindByID", ctx, userID).Return(user, nil)
		mockUserRepo.On("ExistsByEmail", ctx, newEmail).Return(true, nil)

		// Act
		err := authService.RequestChangeEmail(ctx, userID, newEmail)

		// Assert
		assert.Error(t, err)
		assert.Equal(t, domain.ErrEmailInUse, err)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error when repository FindByID fails with database error", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		userID := uuid.New()
		newEmail := "new@example.com"

		expectedError := errors.New("database connection error")
		mockUserRepo.On("FindByID", ctx, userID).Return(nil, expectedError)

		// Act
		err := authService.RequestChangeEmail(ctx, userID, newEmail)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "find user by id")
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error when ExistsByEmail fails with database error", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		userID := uuid.New()
		currentEmail := "current@example.com"
		newEmail := "new@example.com"

		user := &domain.User{
			ID:    userID,
			Email: currentEmail,
		}

		expectedError := errors.New("database connection error")
		mockUserRepo.On("FindByID", ctx, userID).Return(user, nil)
		mockUserRepo.On("ExistsByEmail", ctx, newEmail).Return(false, expectedError)

		// Act
		err := authService.RequestChangeEmail(ctx, userID, newEmail)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "check if email")
		assert.Contains(t, err.Error(), "already exists")
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error when verification token creation fails", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		userID := uuid.New()
		currentEmail := "current@example.com"
		newEmail := "new@example.com"

		user := &domain.User{
			ID:    userID,
			Email: currentEmail,
		}

		expectedError := errors.New("database error")
		mockUserRepo.On("FindByID", ctx, userID).Return(user, nil)
		mockUserRepo.On("ExistsByEmail", ctx, newEmail).Return(false, nil)
		mockVerificationTokenRepo.On("Create", ctx, mock.AnythingOfType("*domain.VerificationToken")).Return(expectedError)

		// Act
		err := authService.RequestChangeEmail(ctx, userID, newEmail)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "create verification token for change email")
		mockUserRepo.AssertExpectations(t)
		mockVerificationTokenRepo.AssertExpectations(t)
	})

	t.Run("should handle case-sensitive email comparison", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{
			URL: config.URL{
				APIBaseURL: "http://localhost:8080",
			},
		}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		userID := uuid.New()
		currentEmail := "user@example.com"
		newEmail := "User@Example.com" // Different case

		user := &domain.User{
			ID:    userID,
			Email: currentEmail,
		}

		mockUserRepo.On("FindByID", ctx, userID).Return(user, nil)
		mockUserRepo.On("ExistsByEmail", ctx, newEmail).Return(false, nil)
		mockVerificationTokenRepo.On("Create", ctx, mock.AnythingOfType("*domain.VerificationToken")).Return(nil)

		// Act
		err := authService.RequestChangeEmail(ctx, userID, newEmail)

		// Assert
		assert.NoError(t, err) // Should allow different case
		mockUserRepo.AssertExpectations(t)
		mockVerificationTokenRepo.AssertExpectations(t)
	})

	t.Run("should create verification token with correct payload", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{
			URL: config.URL{
				APIBaseURL: "http://localhost:8080",
			},
		}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		userID := uuid.New()
		currentEmail := "current@example.com"
		newEmail := "new@example.com"

		user := &domain.User{
			ID:    userID,
			Email: currentEmail,
		}

		mockUserRepo.On("FindByID", ctx, userID).Return(user, nil)
		mockUserRepo.On("ExistsByEmail", ctx, newEmail).Return(false, nil)

		var capturedomainken *domain.VerificationToken
		mockVerificationTokenRepo.On("Create", ctx, mock.MatchedBy(func(token *domain.VerificationToken) bool {
			capturedomainken = token
			return token.Flow == domain.ChangeEmailFlow &&
				token.UserID == userID &&
				token.Payload.Valid &&
				token.Payload.String == newEmail
		})).Return(nil)

		// Act
		err := authService.RequestChangeEmail(ctx, userID, newEmail)

		// Assert
		assert.NoError(t, err)
		assert.NotNil(t, capturedomainken)
		assert.Equal(t, domain.ChangeEmailFlow, capturedomainken.Flow)
		assert.Equal(t, userID, capturedomainken.UserID)
		assert.True(t, capturedomainken.Payload.Valid)
		assert.Equal(t, newEmail, capturedomainken.Payload.String)
		assert.False(t, capturedomainken.IsExpired())
		mockUserRepo.AssertExpectations(t)
		mockVerificationTokenRepo.AssertExpectations(t)
	})
}

func TestAuthService_ChangeEmail(t *testing.T) {
	t.Run("should change email successfully when valid token is provided", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		tokenID := uuid.New()
		userID := uuid.New()
		newEmail := "new@example.com"

		verificationToken := &domain.VerificationToken{
			ID:        tokenID,
			Flow:      domain.ChangeEmailFlow,
			UserID:    userID,
			ExpiresAt: time.Now().Add(time.Hour),
			Payload:   sql.NullString{String: newEmail, Valid: true},
		}

		mockVerificationTokenRepo.On("FindByID", ctx, tokenID).Return(verificationToken, nil)
		mockUserRepo.On("UpdateEmail", ctx, userID, newEmail).Return(nil)
		mockVerificationTokenRepo.On("Delete", ctx, tokenID).Return(nil)

		// Act
		err := authService.ChangeEmail(ctx, tokenID)

		// Assert
		assert.NoError(t, err)
		mockVerificationTokenRepo.AssertExpectations(t)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error when verification token not found", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		tokenID := uuid.New()

		mockVerificationTokenRepo.On("FindByID", ctx, tokenID).Return(nil, repository.ErrVerificationCodeNotFound)

		// Act
		err := authService.ChangeEmail(ctx, tokenID)

		// Assert
		assert.Error(t, err)
		assert.Equal(t, domain.ErrVerificationTokenNotFound, err)
		mockVerificationTokenRepo.AssertExpectations(t)
	})

	t.Run("should return error when verification token is expired", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		tokenID := uuid.New()
		userID := uuid.New()
		newEmail := "new@example.com"

		expiredomainken := &domain.VerificationToken{
			ID:        tokenID,
			Flow:      domain.ChangeEmailFlow,
			UserID:    userID,
			ExpiresAt: time.Now().Add(-time.Hour), // Expired
			Payload:   sql.NullString{String: newEmail, Valid: true},
		}

		mockVerificationTokenRepo.On("FindByID", ctx, tokenID).Return(expiredomainken, nil)

		// Act
		err := authService.ChangeEmail(ctx, tokenID)

		// Assert
		assert.Error(t, err)
		assert.Equal(t, domain.ErrInvalidVerificationToken, err)
		mockVerificationTokenRepo.AssertExpectations(t)
	})

	t.Run("should return error when verification token has wrong flow", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		tokenID := uuid.New()
		userID := uuid.New()
		newEmail := "new@example.com"

		wrongFlowToken := &domain.VerificationToken{
			ID:        tokenID,
			Flow:      domain.VerificationEmailFlow, // Wrong flow
			UserID:    userID,
			ExpiresAt: time.Now().Add(time.Hour),
			Payload:   sql.NullString{String: newEmail, Valid: true},
		}

		mockVerificationTokenRepo.On("FindByID", ctx, tokenID).Return(wrongFlowToken, nil)

		// Act
		err := authService.ChangeEmail(ctx, tokenID)

		// Assert
		assert.Error(t, err)
		assert.Equal(t, domain.ErrInvalidVerificationToken, err)
		mockVerificationTokenRepo.AssertExpectations(t)
	})

	t.Run("should return error when payload is invalid", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		tokenID := uuid.New()
		userID := uuid.New()

		invalidPayloadomainken := &domain.VerificationToken{
			ID:        tokenID,
			Flow:      domain.ChangeEmailFlow,
			UserID:    userID,
			ExpiresAt: time.Now().Add(time.Hour),
			Payload:   sql.NullString{Valid: false}, // Invalid payload
		}

		mockVerificationTokenRepo.On("FindByID", ctx, tokenID).Return(invalidPayloadomainken, nil)

		// Act
		err := authService.ChangeEmail(ctx, tokenID)

		// Assert
		assert.Error(t, err)
		assert.Equal(t, domain.ErrInvalidVerificationTokenPayload, err)
		mockVerificationTokenRepo.AssertExpectations(t)
	})

	t.Run("should return error when email update fails", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		tokenID := uuid.New()
		userID := uuid.New()
		newEmail := "new@example.com"

		verificationToken := &domain.VerificationToken{
			ID:        tokenID,
			Flow:      domain.ChangeEmailFlow,
			UserID:    userID,
			ExpiresAt: time.Now().Add(time.Hour),
			Payload:   sql.NullString{String: newEmail, Valid: true},
		}

		expectedError := errors.New("database update error")
		mockVerificationTokenRepo.On("FindByID", ctx, tokenID).Return(verificationToken, nil)
		mockUserRepo.On("UpdateEmail", ctx, userID, newEmail).Return(expectedError)

		// Act
		err := authService.ChangeEmail(ctx, tokenID)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "update email for userId")
		mockVerificationTokenRepo.AssertExpectations(t)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error when token deletion fails", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		tokenID := uuid.New()
		userID := uuid.New()
		newEmail := "new@example.com"

		verificationToken := &domain.VerificationToken{
			ID:        tokenID,
			Flow:      domain.ChangeEmailFlow,
			UserID:    userID,
			ExpiresAt: time.Now().Add(time.Hour),
			Payload:   sql.NullString{String: newEmail, Valid: true},
		}

		expectedError := errors.New("database delete error")
		mockVerificationTokenRepo.On("FindByID", ctx, tokenID).Return(verificationToken, nil)
		mockUserRepo.On("UpdateEmail", ctx, userID, newEmail).Return(nil)
		mockVerificationTokenRepo.On("Delete", ctx, tokenID).Return(expectedError)

		// Act
		err := authService.ChangeEmail(ctx, tokenID)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "delete verification token with id")
		mockVerificationTokenRepo.AssertExpectations(t)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error when repository FindByID fails with database error", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		tokenID := uuid.New()

		expectedError := errors.New("database connection error")
		mockVerificationTokenRepo.On("FindByID", ctx, tokenID).Return(nil, expectedError)

		// Act
		err := authService.ChangeEmail(ctx, tokenID)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "find verification token by id")
		mockVerificationTokenRepo.AssertExpectations(t)
	})

	t.Run("should handle empty payload string", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		tokenID := uuid.New()
		userID := uuid.New()

		emptyPayloadomainken := &domain.VerificationToken{
			ID:        tokenID,
			Flow:      domain.ChangeEmailFlow,
			UserID:    userID,
			ExpiresAt: time.Now().Add(time.Hour),
			Payload:   sql.NullString{String: "", Valid: true}, // Valid but empty
		}

		mockVerificationTokenRepo.On("FindByID", ctx, tokenID).Return(emptyPayloadomainken, nil)
		mockUserRepo.On("UpdateEmail", ctx, userID, "").Return(nil)
		mockVerificationTokenRepo.On("Delete", ctx, tokenID).Return(nil)

		// Act
		err := authService.ChangeEmail(ctx, tokenID)

		// Assert
		assert.NoError(t, err) // Should succeed with empty email (edge case)
		mockVerificationTokenRepo.AssertExpectations(t)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should extract correct email from payload", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		tokenID := uuid.New()
		userID := uuid.New()
		expectedNewEmail := "test@example.com"

		verificationToken := &domain.VerificationToken{
			ID:        tokenID,
			Flow:      domain.ChangeEmailFlow,
			UserID:    userID,
			ExpiresAt: time.Now().Add(time.Hour),
			Payload:   sql.NullString{String: expectedNewEmail, Valid: true},
		}

		mockVerificationTokenRepo.On("FindByID", ctx, tokenID).Return(verificationToken, nil)
		mockUserRepo.On("UpdateEmail", ctx, userID, expectedNewEmail).Return(nil)
		mockVerificationTokenRepo.On("Delete", ctx, tokenID).Return(nil)

		// Act
		err := authService.ChangeEmail(ctx, tokenID)

		// Assert
		assert.NoError(t, err)
		mockVerificationTokenRepo.AssertExpectations(t)
		mockUserRepo.AssertExpectations(t)
	})
}

func TestAuthService_VerifyEmail(t *testing.T) {
	t.Run("should verify email successfully when valid token is provided", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		mockSessionService := mocks.NewSessionServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mockSessionService,
		)

		ctx := context.Background()
		tokenID := uuid.New()
		userID := uuid.New()

		verificationToken := &domain.VerificationToken{
			ID:        tokenID,
			Flow:      domain.VerificationEmailFlow,
			UserID:    userID,
			ExpiresAt: time.Now().Add(time.Hour),
		}

		expectedAccessToken := &model.AccessToken{
			Value:     "test-jwt-token",
			ExpiresAt: time.Now().Add(2 * time.Hour),
		}

		expectedSession := &domain.Session{
			ID:         uuid.New(),
			DeviceName: "test-device",
			IPAddress:  "127.0.0.1",
			UserAgent:  "test-agent",
		}

		mockVerificationTokenRepo.On("FindByID", ctx, tokenID).Return(verificationToken, nil)
		mockUserRepo.On("VerifyEmail", ctx, userID).Return(nil)
		mockVerificationTokenRepo.On("Delete", ctx, tokenID).Return(nil)
		mockSessionService.On("CreateSession", ctx, userID, "127.0.0.1", "test-device", "test-agent").Return(expectedSession, nil)
		mockJwtService.On("GenerateAccessTokenJWT", ctx, userID, expectedSession.ID).Return(expectedAccessToken, nil)

		// Act
		result, err := authService.VerifyEmail(ctx, model.VerifyEmailInput{
			Token:      tokenID,
			IPAddress:  "127.0.0.1",
			UserAgent:  "test-agent",
			DeviceName: "test-device",
		})

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, expectedAccessToken, result)
		mockVerificationTokenRepo.AssertExpectations(t)
		mockUserRepo.AssertExpectations(t)
		mockJwtService.AssertExpectations(t)
		mockSessionService.AssertExpectations(t)
	})

	t.Run("should return error when verification token not found", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		tokenID := uuid.New()

		mockVerificationTokenRepo.On("FindByID", ctx, tokenID).Return(nil, repository.ErrVerificationCodeNotFound)

		// Act
		result, err := authService.VerifyEmail(ctx, model.VerifyEmailInput{
			Token:      tokenID,
			IPAddress:  "127.0.0.1",
			UserAgent:  "test-agent",
			DeviceName: "test-device",
		})

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, domain.ErrVerificationTokenNotFound, err)
		mockVerificationTokenRepo.AssertExpectations(t)
	})

	t.Run("should return error when verification token is expired", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		tokenID := uuid.New()
		userID := uuid.New()

		expiredomainken := &domain.VerificationToken{
			ID:        tokenID,
			Flow:      domain.VerificationEmailFlow,
			UserID:    userID,
			ExpiresAt: time.Now().Add(-time.Hour), // Expired
		}

		mockVerificationTokenRepo.On("FindByID", ctx, tokenID).Return(expiredomainken, nil)

		// Act
		result, err := authService.VerifyEmail(ctx, model.VerifyEmailInput{
			Token:      tokenID,
			IPAddress:  "127.0.0.1",
			UserAgent:  "test-agent",
			DeviceName: "test-device",
		})

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, domain.ErrInvalidVerificationToken, err)
		mockVerificationTokenRepo.AssertExpectations(t)
	})

	t.Run("should return error when verification token has wrong flow", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		tokenID := uuid.New()
		userID := uuid.New()

		wrongFlowToken := &domain.VerificationToken{
			ID:        tokenID,
			Flow:      domain.ResetPasswordFlow, // Wrong flow
			UserID:    userID,
			ExpiresAt: time.Now().Add(time.Hour),
		}

		mockVerificationTokenRepo.On("FindByID", ctx, tokenID).Return(wrongFlowToken, nil)

		// Act
		result, err := authService.VerifyEmail(ctx, model.VerifyEmailInput{
			Token:      tokenID,
			IPAddress:  "127.0.0.1",
			UserAgent:  "test-agent",
			DeviceName: "test-device",
		})

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, domain.ErrInvalidVerificationToken, err)
		mockVerificationTokenRepo.AssertExpectations(t)
	})

	t.Run("should return error when user verification fails", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		tokenID := uuid.New()
		userID := uuid.New()

		verificationToken := &domain.VerificationToken{
			ID:        tokenID,
			Flow:      domain.VerificationEmailFlow,
			UserID:    userID,
			ExpiresAt: time.Now().Add(time.Hour),
		}

		expectedError := errors.New("database error")
		mockVerificationTokenRepo.On("FindByID", ctx, tokenID).Return(verificationToken, nil)
		mockUserRepo.On("VerifyEmail", ctx, userID).Return(expectedError)

		// Act
		result, err := authService.VerifyEmail(ctx, model.VerifyEmailInput{
			Token:      tokenID,
			IPAddress:  "127.0.0.1",
			UserAgent:  "test-agent",
			DeviceName: "test-device",
		})

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "verify user email")
		mockVerificationTokenRepo.AssertExpectations(t)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error when token deletion fails", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		tokenID := uuid.New()
		userID := uuid.New()

		verificationToken := &domain.VerificationToken{
			ID:        tokenID,
			Flow:      domain.VerificationEmailFlow,
			UserID:    userID,
			ExpiresAt: time.Now().Add(time.Hour),
		}

		expectedError := errors.New("database error")
		mockVerificationTokenRepo.On("FindByID", ctx, tokenID).Return(verificationToken, nil)
		mockUserRepo.On("VerifyEmail", ctx, userID).Return(nil)
		mockVerificationTokenRepo.On("Delete", ctx, tokenID).Return(expectedError)

		// Act
		result, err := authService.VerifyEmail(ctx, model.VerifyEmailInput{
			Token:      tokenID,
			IPAddress:  "127.0.0.1",
			UserAgent:  "test-agent",
			DeviceName: "test-device",
		})

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "delete verificationCode")
		mockVerificationTokenRepo.AssertExpectations(t)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error when JWT generation fails", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		mockSessionService := mocks.NewSessionServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mockSessionService,
		)

		ctx := context.Background()
		tokenID := uuid.New()
		userID := uuid.New()

		verificationToken := &domain.VerificationToken{
			ID:        tokenID,
			Flow:      domain.VerificationEmailFlow,
			UserID:    userID,
			ExpiresAt: time.Now().Add(time.Hour),
		}

		expectedSession := &domain.Session{
			ID:         uuid.New(),
			DeviceName: "test-device",
			IPAddress:  "127.0.0.1",
			UserAgent:  "test-agent",
		}

		expectedError := errors.New("jwt error")
		mockVerificationTokenRepo.On("FindByID", ctx, tokenID).Return(verificationToken, nil)
		mockUserRepo.On("VerifyEmail", ctx, userID).Return(nil)
		mockVerificationTokenRepo.On("Delete", ctx, tokenID).Return(nil)
		mockSessionService.On("CreateSession", ctx, userID, "127.0.0.1", "test-device", "test-agent").Return(expectedSession, nil)
		mockJwtService.On("GenerateAccessTokenJWT", ctx, userID, expectedSession.ID).Return(nil, expectedError)

		// Act
		result, err := authService.VerifyEmail(ctx, model.VerifyEmailInput{
			Token:      tokenID,
			IPAddress:  "127.0.0.1",
			UserAgent:  "test-agent",
			DeviceName: "test-device",
		})

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "generate accessToken")
		mockVerificationTokenRepo.AssertExpectations(t)
		mockUserRepo.AssertExpectations(t)
		mockJwtService.AssertExpectations(t)
		mockSessionService.AssertExpectations(t)
	})

	t.Run("should return error when repository FindByID fails with other error", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		tokenID := uuid.New()

		expectedError := errors.New("database connection error")
		mockVerificationTokenRepo.On("FindByID", ctx, tokenID).Return(nil, expectedError)

		// Act
		result, err := authService.VerifyEmail(ctx, model.VerifyEmailInput{
			Token:      tokenID,
			IPAddress:  "127.0.0.1",
			UserAgent:  "test-agent",
			DeviceName: "test-device",
		})

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "find verification token by id")
		mockVerificationTokenRepo.AssertExpectations(t)
	})
}

func TestAuthService_Login(t *testing.T) {
	t.Run("should login successfully when credentials are valid and email is verified", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		mockSessionService := mocks.NewSessionServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mockSessionService,
		)

		ctx := context.Background()
		email := "john@example.com"
		password := "password123"
		userID := uuid.New()

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		user := &domain.User{
			ID:               userID,
			Email:            email,
			PasswordHash:     string(hashedPassword),
			Status:           domain.ActiveStatus,
			EmailConfirmedAt: sql.NullTime{Time: time.Now(), Valid: true},
		}

		expectedAccessToken := &model.AccessToken{
			Value:     "test-jwt-token",
			ExpiresAt: time.Now().Add(2 * time.Hour),
		}

		expectedSession := &domain.Session{
			ID:         uuid.New(),
			DeviceName: "test-device",
			IPAddress:  "127.0.0.1",
			UserAgent:  "test-agent",
		}

		mockUserRepo.On("FindByEmail", ctx, email).Return(user, nil)
		mockSessionService.On("CreateSession", ctx, userID, "127.0.0.1", "test-device", "test-agent").Return(expectedSession, nil)
		mockJwtService.On("GenerateAccessTokenJWT", ctx, userID, expectedSession.ID).Return(expectedAccessToken, nil)

		// Act
		result, err := authService.Login(ctx, model.LoginInput{
			Email:      email,
			Password:   password,
			IPAddress:  "127.0.0.1",
			UserAgent:  "test-agent",
			DeviceName: "test-device",
		})

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, expectedAccessToken, result)
		mockUserRepo.AssertExpectations(t)
		mockJwtService.AssertExpectations(t)
		mockSessionService.AssertExpectations(t)
	})

	t.Run("should return error when user not found", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		email := "nonexistent@example.com"
		password := "password123"

		mockUserRepo.On("FindByEmail", ctx, email).Return(nil, repository.ErrUserNotFound)

		// Act
		result, err := authService.Login(ctx, model.LoginInput{
			Email:      email,
			Password:   password,
			IPAddress:  "127.0.0.1",
			UserAgent:  "test-agent",
			DeviceName: "test-device",
		})

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, domain.ErrInvalidCredentials, err)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error when password is invalid", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		email := "john@example.com"
		password := "wrongpassword"
		userID := uuid.New()

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)
		user := &domain.User{
			ID:           userID,
			Email:        email,
			PasswordHash: string(hashedPassword),
		}

		mockUserRepo.On("FindByEmail", ctx, email).Return(user, nil)

		// Act
		result, err := authService.Login(ctx, model.LoginInput{
			Email:      email,
			Password:   password,
			IPAddress:  "127.0.0.1",
			UserAgent:  "test-agent",
			DeviceName: "test-device",
		})

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, domain.ErrInvalidCredentials, err)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error when user is blocked", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		email := "blocked@example.com"
		password := "password123"
		userID := uuid.New()

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		user := &domain.User{
			ID:           userID,
			Email:        email,
			PasswordHash: string(hashedPassword),
			Status:       domain.BlockedStatus,
		}

		mockUserRepo.On("FindByEmail", ctx, email).Return(user, nil)

		// Act
		result, err := authService.Login(ctx, model.LoginInput{
			Email:      email,
			Password:   password,
			IPAddress:  "127.0.0.1",
			UserAgent:  "test-agent",
			DeviceName: "test-device",
		})

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, domain.ErrUserBlocked, err)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error when email is not verified", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{
			URL: config.URL{
				APIBaseURL: "http://localhost:8080",
			},
		}

		mockEmailNotification := mocks.NewEmailNotificationMock(t)
		mockEmailNotification.On("SendWelcomeEmail", mock.Anything, mock.AnythingOfType("time.Time"), mock.Anything, mock.AnythingOfType("string"), mock.Anything).Maybe().Return(nil)

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mockEmailNotification,
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		email := "unverified@example.com"
		password := "password123"
		userID := uuid.New()

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		user := &domain.User{
			ID:               userID,
			Email:            email,
			PasswordHash:     string(hashedPassword),
			Status:           domain.PendingStatus,
			EmailConfirmedAt: sql.NullTime{Valid: false},
		}

		// Mock handleUnverifiedEmail behavior - no existing token
		mockUserRepo.On("FindByEmail", ctx, email).Return(user, nil)
		mockVerificationTokenRepo.On("FindValidByUserIDAndFlow", ctx, userID, domain.VerificationEmailFlow).Return(nil, repository.ErrVerificationCodeNotFound)
		mockVerificationTokenRepo.On("InvalidateByUserIDAndFlow", ctx, userID, domain.VerificationEmailFlow).Return(nil)
		mockVerificationTokenRepo.On("Create", ctx, mock.AnythingOfType("*domain.VerificationToken")).Return(nil)

		// Act
		result, err := authService.Login(ctx, model.LoginInput{
			Email:      email,
			Password:   password,
			IPAddress:  "127.0.0.1",
			UserAgent:  "test-agent",
			DeviceName: "test-device",
		})

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, domain.ErrEmailNotVerified, err)
		mockUserRepo.AssertExpectations(t)
		mockVerificationTokenRepo.AssertExpectations(t)
	})

	t.Run("should return error when JWT generation fails", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		mockSessionService := mocks.NewSessionServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mockSessionService,
		)

		ctx := context.Background()
		email := "john@example.com"
		password := "password123"
		userID := uuid.New()

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		user := &domain.User{
			ID:               userID,
			Email:            email,
			PasswordHash:     string(hashedPassword),
			Status:           domain.ActiveStatus,
			EmailConfirmedAt: sql.NullTime{Time: time.Now(), Valid: true},
		}

		expectedSession := &domain.Session{
			ID:         uuid.New(),
			DeviceName: "test-device",
			IPAddress:  "127.0.0.1",
			UserAgent:  "test-agent",
		}

		expectedError := errors.New("jwt generation failed")
		mockUserRepo.On("FindByEmail", ctx, email).Return(user, nil)
		mockSessionService.On("CreateSession", ctx, userID, "127.0.0.1", "test-device", "test-agent").Return(expectedSession, nil)
		mockJwtService.On("GenerateAccessTokenJWT", ctx, userID, expectedSession.ID).Return(nil, expectedError)

		// Act
		result, err := authService.Login(ctx, model.LoginInput{
			Email:      email,
			Password:   password,
			IPAddress:  "127.0.0.1",
			UserAgent:  "test-agent",
			DeviceName: "test-device",
		})

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "generate access token")
		mockUserRepo.AssertExpectations(t)
		mockJwtService.AssertExpectations(t)
		mockSessionService.AssertExpectations(t)
	})

	t.Run("should return error when repository FindByEmail fails with database error", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mocks.NewEmailNotificationMock(t),
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		email := "john@example.com"
		password := "password123"

		expectedError := errors.New("database connection error")
		mockUserRepo.On("FindByEmail", ctx, email).Return(nil, expectedError)

		// Act
		result, err := authService.Login(ctx, model.LoginInput{
			Email:      email,
			Password:   password,
			IPAddress:  "127.0.0.1",
			UserAgent:  "test-agent",
			DeviceName: "test-device",
		})

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "find user by email")
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error when handleUnverifiedEmail fails", func(t *testing.T) {
		// Arrange
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		config := &config.Config{}

		mockEmailNotification := mocks.NewEmailNotificationMock(t)
		mockEmailNotification.On("SendWelcomeEmail", mock.Anything, mock.AnythingOfType("time.Time"), mock.Anything, mock.AnythingOfType("string"), mock.Anything).Maybe().Return(nil)

		authService := service.NewAuthService(
			mockUserRepo,
			mockVerificationTokenRepo,
			mockJwtService,
			config,
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			mockEmailNotification,
			mocks.NewSessionServiceMock(t),
		)

		ctx := context.Background()
		email := "unverified@example.com"
		password := "password123"
		userID := uuid.New()

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		user := &domain.User{
			ID:               userID,
			Email:            email,
			PasswordHash:     string(hashedPassword),
			Status:           domain.PendingStatus,
			EmailConfirmedAt: sql.NullTime{Valid: false},
		}

		expectedError := errors.New("verification token creation failed")
		mockUserRepo.On("FindByEmail", ctx, email).Return(user, nil)
		mockVerificationTokenRepo.On("FindValidByUserIDAndFlow", ctx, userID, domain.VerificationEmailFlow).Return(nil, repository.ErrVerificationCodeNotFound)
		mockVerificationTokenRepo.On("InvalidateByUserIDAndFlow", ctx, userID, domain.VerificationEmailFlow).Return(nil)
		mockVerificationTokenRepo.On("Create", ctx, mock.AnythingOfType("*domain.VerificationToken")).Return(expectedError)

		// Act
		result, err := authService.Login(ctx, model.LoginInput{
			Email:      email,
			Password:   password,
			IPAddress:  "127.0.0.1",
			UserAgent:  "test-agent",
			DeviceName: "test-device",
		})

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "handle unverified email")
		mockUserRepo.AssertExpectations(t)
		mockVerificationTokenRepo.AssertExpectations(t)
	})
}

func TestAuthService_RequestPasswordReset(t *testing.T) {
	t.Run("should create a verification token and return no error when email exists", func(t *testing.T) {
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		mockConfig := &config.Config{
			URL: config.URL{
				APIBaseURL: "http://localhost:8080",
			},
		}

		mockEmailNotification := mocks.NewEmailNotificationMock(t)
		// Allow the goroutine to call SendResetPasswordEmail without strict expectations
		mockEmailNotification.On("SendResetPasswordEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
		authService := service.NewAuthService(mockUserRepo, mockVerificationTokenRepo, mockJwtService, mockConfig, slog.New(slog.NewTextHandler(os.Stdout, nil)), mockEmailNotification, mocks.NewSessionServiceMock(t))

		email := "test@example.com"
		userID := uuid.New()
		mockUser := &domain.User{
			ID:    userID,
			Email: email,
		}

		mockUserRepo.On("FindByEmail", mock.Anything, email).Return(mockUser, nil)
		mockVerificationTokenRepo.On("Create", mock.Anything, mock.Anything).Return(nil)

		err := authService.RequestPasswordReset(context.Background(), email)

		assert.NoError(t, err)
		mockUserRepo.AssertExpectations(t)
		mockVerificationTokenRepo.AssertExpectations(t)
	})

	t.Run("should return no error when email does not exist to prevent enumeration", func(t *testing.T) {
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		mockConfig := &config.Config{
			URL: config.URL{
				APIBaseURL: "http://localhost:8080",
			},
		}

		authService := service.NewAuthService(mockUserRepo, mockVerificationTokenRepo, mockJwtService, mockConfig, slog.New(slog.NewTextHandler(os.Stdout, nil)), mocks.NewEmailNotificationMock(t), mocks.NewSessionServiceMock(t))

		email := "nonexistent@example.com"

		mockUserRepo.On("FindByEmail", mock.Anything, email).Return(nil, repository.ErrUserNotFound)

		err := authService.RequestPasswordReset(context.Background(), email)

		assert.Equal(t, domain.ErrUserNotFound, err)
		mockUserRepo.AssertExpectations(t)
	})
}

func TestAuthService_ResetPassword(t *testing.T) {
	t.Run("should reset password successfully with valid token", func(t *testing.T) {
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		mockConfig := &config.Config{}

		authService := service.NewAuthService(mockUserRepo, mockVerificationTokenRepo, mockJwtService, mockConfig, slog.New(slog.NewTextHandler(os.Stdout, nil)), mocks.NewEmailNotificationMock(t), mocks.NewSessionServiceMock(t))

		token := uuid.New()
		newPassword := "newSecurePassword"
		userID := uuid.New()
		mockVerificationToken := &domain.VerificationToken{
			ID:        token,
			UserID:    userID,
			ExpiresAt: time.Now().Add(10 * time.Minute),
			Flow:      domain.ResetPasswordFlow,
		}

		mockVerificationTokenRepo.On("FindByID", mock.Anything, token).Return(mockVerificationToken, nil)
		mockUserRepo.On("UpdatePassword", mock.Anything, userID, mock.Anything).Return(nil)
		mockVerificationTokenRepo.On("Delete", mock.Anything, token).Return(nil)

		accessToken, err := authService.ResetPassword(context.Background(), token, newPassword)

		assert.NoError(t, err)
		assert.Nil(t, accessToken)
		mockVerificationTokenRepo.AssertExpectations(t)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error for expired or invalid token", func(t *testing.T) {
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		mockConfig := &config.Config{}

		authService := service.NewAuthService(mockUserRepo, mockVerificationTokenRepo, mockJwtService, mockConfig, slog.New(slog.NewTextHandler(os.Stdout, nil)), mocks.NewEmailNotificationMock(t), mocks.NewSessionServiceMock(t))

		token := uuid.New()
		mockVerificationToken := &domain.VerificationToken{
			ID:        token,
			ExpiresAt: time.Now().Add(-10 * time.Minute),
			Flow:      domain.ResetPasswordFlow,
		}

		mockVerificationTokenRepo.On("FindByID", mock.Anything, token).Return(mockVerificationToken, nil)

		accessToken, err := authService.ResetPassword(context.Background(), token, "newPassword")

		assert.Error(t, err)
		assert.Nil(t, accessToken)
		assert.Equal(t, domain.ErrInvalidVerificationToken, err)
		mockVerificationTokenRepo.AssertExpectations(t)
	})

	t.Run("should return error if password update fails", func(t *testing.T) {
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		mockConfig := &config.Config{}

		authService := service.NewAuthService(mockUserRepo, mockVerificationTokenRepo, mockJwtService, mockConfig, slog.New(slog.NewTextHandler(os.Stdout, nil)), mocks.NewEmailNotificationMock(t), mocks.NewSessionServiceMock(t))

		token := uuid.New()
		newPassword := "newSecurePassword"
		userID := uuid.New()
		mockVerificationToken := &domain.VerificationToken{
			ID:        token,
			UserID:    userID,
			ExpiresAt: time.Now().Add(10 * time.Minute),
			Flow:      domain.ResetPasswordFlow,
		}

		mockVerificationTokenRepo.On("FindByID", mock.Anything, token).Return(mockVerificationToken, nil)
		mockUserRepo.On("UpdatePassword", mock.Anything, userID, mock.Anything).Return(errors.New("update error"))

		accessToken, err := authService.ResetPassword(context.Background(), token, newPassword)

		assert.Error(t, err)
		assert.Nil(t, accessToken)
		mockVerificationTokenRepo.AssertExpectations(t)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("should return error if token deletion fails", func(t *testing.T) {
		mockUserRepo := mocks.NewUserRepositoryMock(t)
		mockVerificationTokenRepo := mocks.NewVerificationTokenRepositoryMock(t)
		mockJwtService := mocks.NewJwtServiceMock(t)
		mockConfig := &config.Config{}

		authService := service.NewAuthService(mockUserRepo, mockVerificationTokenRepo, mockJwtService, mockConfig, slog.New(slog.NewTextHandler(os.Stdout, nil)), mocks.NewEmailNotificationMock(t), mocks.NewSessionServiceMock(t))

		token := uuid.New()
		newPassword := "newSecurePassword"
		userID := uuid.New()
		mockVerificationToken := &domain.VerificationToken{
			ID:        token,
			UserID:    userID,
			ExpiresAt: time.Now().Add(10 * time.Minute),
			Flow:      domain.ResetPasswordFlow,
		}

		mockVerificationTokenRepo.On("FindByID", mock.Anything, token).Return(mockVerificationToken, nil)
		mockUserRepo.On("UpdatePassword", mock.Anything, userID, mock.Anything).Return(nil)
		mockVerificationTokenRepo.On("Delete", mock.Anything, token).Return(errors.New("delete error"))

		accessToken, err := authService.ResetPassword(context.Background(), token, newPassword)

		assert.Error(t, err)
		assert.Nil(t, accessToken)
		mockVerificationTokenRepo.AssertExpectations(t)
		mockUserRepo.AssertExpectations(t)
	})
}
