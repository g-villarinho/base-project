package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/g-villarinho/base-project/config"
	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/g-villarinho/base-project/internal/mocks"
	"github.com/g-villarinho/base-project/internal/repository"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func setupSessionService(t *testing.T) (SessionService, *mocks.SessionRepositoryMock) {
	t.Helper()

	sessionRepoMock := mocks.NewSessionRepositoryMock(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := &config.Config{
		Session: config.Session{
			Duration: 24 * time.Hour,
		},
	}

	service := NewSessionService(sessionRepoMock, cfg, logger)
	return service, sessionRepoMock
}

func TestCreateSession(t *testing.T) {
	t.Run("should create session successfully with valid parameters", func(t *testing.T) {
		// Arrange
		service, sessionRepoMock := setupSessionService(t)

		ctx := context.Background()
		userID := uuid.New()
		ipAddress := "192.168.1.1"
		deviceName := "MacBook Pro"
		userAgent := "Mozilla/5.0"

		sessionRepoMock.On("Create", ctx, mock.AnythingOfType("*domain.Session")).
			Return(nil)

		// Act
		session, err := service.CreateSession(ctx, userID, ipAddress, deviceName, userAgent)

		// Assert
		require.NoError(t, err)
		assert.NotNil(t, session)
		assert.Equal(t, userID, session.UserID)
		assert.Equal(t, ipAddress, session.IPAddress)
		assert.Equal(t, deviceName, session.DeviceName)
		assert.Equal(t, userAgent, session.UserAgent)
		assert.NotEmpty(t, session.Token)
		assert.False(t, session.ExpiresAt.IsZero())
		assert.True(t, session.ExpiresAt.After(time.Now().UTC()))
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository create fails", func(t *testing.T) {
		// Arrange
		service, sessionRepoMock := setupSessionService(t)

		ctx := context.Background()
		userID := uuid.New()
		ipAddress := "192.168.1.1"
		deviceName := "MacBook Pro"
		userAgent := "Mozilla/5.0"

		expectedErr := errors.New("database error")
		sessionRepoMock.On("Create", ctx, mock.AnythingOfType("*domain.Session")).
			Return(expectedErr)

		// Act
		session, err := service.CreateSession(ctx, userID, ipAddress, deviceName, userAgent)

		// Assert
		require.Error(t, err)
		assert.Nil(t, session)
		assert.Contains(t, err.Error(), "persist new session")
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should set correct expiration time based on config", func(t *testing.T) {
		// Arrange
		service, sessionRepoMock := setupSessionService(t)

		ctx := context.Background()
		userID := uuid.New()
		ipAddress := "192.168.1.1"
		deviceName := "MacBook Pro"
		userAgent := "Mozilla/5.0"

		var capturedSession *domain.Session
		sessionRepoMock.On("Create", ctx, mock.AnythingOfType("*domain.Session")).
			Run(func(args mock.Arguments) {
				capturedSession = args.Get(1).(*domain.Session)
			}).
			Return(nil)

		// Act
		session, err := service.CreateSession(ctx, userID, ipAddress, deviceName, userAgent)

		// Assert
		require.NoError(t, err)
		assert.NotNil(t, session)
		assert.NotNil(t, capturedSession)

		expectedExpiration := time.Now().UTC().Add(24 * time.Hour)
		assert.WithinDuration(t, expectedExpiration, session.ExpiresAt, 5*time.Second)
		sessionRepoMock.AssertExpectations(t)
	})
}

func TestFindSessionByToken(t *testing.T) {
	t.Run("should return session when valid token is provided", func(t *testing.T) {
		// Arrange
		service, sessionRepoMock := setupSessionService(t)

		ctx := context.Background()
		token := "valid-token-123"
		sessionID := uuid.New()
		userID := uuid.New()

		expectedSession := &domain.Session{
			ID:         sessionID,
			Token:      token,
			UserID:     userID,
			DeviceName: "MacBook Pro",
			IPAddress:  "192.168.1.1",
			UserAgent:  "Mozilla/5.0",
			ExpiresAt:  time.Now().UTC().Add(24 * time.Hour),
			CreatedAt:  time.Now().UTC(),
		}

		sessionRepoMock.On("FindByToken", ctx, token).
			Return(expectedSession, nil)

		// Act
		session, err := service.FindSessionByToken(ctx, token)

		// Assert
		require.NoError(t, err)
		assert.NotNil(t, session)
		assert.Equal(t, expectedSession.ID, session.ID)
		assert.Equal(t, expectedSession.Token, session.Token)
		assert.Equal(t, expectedSession.UserID, session.UserID)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when session is not found", func(t *testing.T) {
		// Arrange
		service, sessionRepoMock := setupSessionService(t)

		ctx := context.Background()
		token := "non-existent-token"

		sessionRepoMock.On("FindByToken", ctx, token).
			Return(nil, repository.ErrSessionNotFound)

		// Act
		session, err := service.FindSessionByToken(ctx, token)

		// Assert
		require.Error(t, err)
		assert.Nil(t, session)
		assert.Equal(t, domain.ErrSessionNotFound, err)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when session is expired", func(t *testing.T) {
		// Arrange
		service, sessionRepoMock := setupSessionService(t)

		ctx := context.Background()
		token := "expired-token"
		sessionID := uuid.New()
		userID := uuid.New()

		expiredSession := &domain.Session{
			ID:         sessionID,
			Token:      token,
			UserID:     userID,
			DeviceName: "MacBook Pro",
			IPAddress:  "192.168.1.1",
			UserAgent:  "Mozilla/5.0",
			ExpiresAt:  time.Now().UTC().Add(-24 * time.Hour), // Expired
			CreatedAt:  time.Now().UTC().Add(-48 * time.Hour),
		}

		sessionRepoMock.On("FindByToken", ctx, token).
			Return(expiredSession, nil)

		// Act
		session, err := service.FindSessionByToken(ctx, token)

		// Assert
		require.Error(t, err)
		assert.Nil(t, session)
		assert.Equal(t, domain.ErrSessionExpired, err)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository fails", func(t *testing.T) {
		// Arrange
		service, sessionRepoMock := setupSessionService(t)

		ctx := context.Background()
		token := "valid-token"

		expectedErr := errors.New("database connection error")
		sessionRepoMock.On("FindByToken", ctx, token).
			Return(nil, expectedErr)

		// Act
		session, err := service.FindSessionByToken(ctx, token)

		// Assert
		require.Error(t, err)
		assert.Nil(t, session)
		assert.Contains(t, err.Error(), "find session by token")
		sessionRepoMock.AssertExpectations(t)
	})
}

func TestDeleteSessionByID(t *testing.T) {
	t.Run("should delete session successfully when valid IDs are provided", func(t *testing.T) {
		// Arrange
		service, sessionRepoMock := setupSessionService(t)

		ctx := context.Background()
		userID := uuid.New()
		sessionID := uuid.New()

		existingSession := &domain.Session{
			ID:         sessionID,
			Token:      "valid-token",
			UserID:     userID,
			DeviceName: "MacBook Pro",
			IPAddress:  "192.168.1.1",
			UserAgent:  "Mozilla/5.0",
			ExpiresAt:  time.Now().UTC().Add(24 * time.Hour),
			CreatedAt:  time.Now().UTC(),
		}

		sessionRepoMock.On("FindByID", ctx, sessionID).
			Return(existingSession, nil)
		sessionRepoMock.On("DeleteByID", ctx, sessionID).
			Return(nil)

		// Act
		err := service.DeleteSessionByID(ctx, userID, sessionID)

		// Assert
		require.NoError(t, err)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when session is not found", func(t *testing.T) {
		// Arrange
		service, sessionRepoMock := setupSessionService(t)

		ctx := context.Background()
		userID := uuid.New()
		sessionID := uuid.New()

		sessionRepoMock.On("FindByID", ctx, sessionID).
			Return(nil, repository.ErrSessionNotFound)

		// Act
		err := service.DeleteSessionByID(ctx, userID, sessionID)

		// Assert
		require.Error(t, err)
		assert.Equal(t, domain.ErrSessionNotFound, err)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when session does not belong to user", func(t *testing.T) {
		// Arrange
		service, sessionRepoMock := setupSessionService(t)

		ctx := context.Background()
		userID := uuid.New()
		otherUserID := uuid.New()
		sessionID := uuid.New()

		existingSession := &domain.Session{
			ID:         sessionID,
			Token:      "valid-token",
			UserID:     otherUserID, // Different user
			DeviceName: "MacBook Pro",
			IPAddress:  "192.168.1.1",
			UserAgent:  "Mozilla/5.0",
			ExpiresAt:  time.Now().UTC().Add(24 * time.Hour),
			CreatedAt:  time.Now().UTC(),
		}

		sessionRepoMock.On("FindByID", ctx, sessionID).
			Return(existingSession, nil)

		// Act
		err := service.DeleteSessionByID(ctx, userID, sessionID)

		// Assert
		require.Error(t, err)
		assert.Equal(t, domain.ErrSessionNotBelong, err)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return nil when session is already expired", func(t *testing.T) {
		// Arrange
		service, sessionRepoMock := setupSessionService(t)

		ctx := context.Background()
		userID := uuid.New()
		sessionID := uuid.New()

		expiredSession := &domain.Session{
			ID:         sessionID,
			Token:      "expired-token",
			UserID:     userID,
			DeviceName: "MacBook Pro",
			IPAddress:  "192.168.1.1",
			UserAgent:  "Mozilla/5.0",
			ExpiresAt:  time.Now().UTC().Add(-24 * time.Hour), // Expired
			CreatedAt:  time.Now().UTC().Add(-48 * time.Hour),
		}

		sessionRepoMock.On("FindByID", ctx, sessionID).
			Return(expiredSession, nil)

		// Act
		err := service.DeleteSessionByID(ctx, userID, sessionID)

		// Assert
		require.NoError(t, err)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository find fails", func(t *testing.T) {
		// Arrange
		service, sessionRepoMock := setupSessionService(t)

		ctx := context.Background()
		userID := uuid.New()
		sessionID := uuid.New()

		expectedErr := errors.New("database error")
		sessionRepoMock.On("FindByID", ctx, sessionID).
			Return(nil, expectedErr)

		// Act
		err := service.DeleteSessionByID(ctx, userID, sessionID)

		// Assert
		require.Error(t, err)
		assert.Contains(t, err.Error(), "find session by id")
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository delete fails", func(t *testing.T) {
		// Arrange
		service, sessionRepoMock := setupSessionService(t)

		ctx := context.Background()
		userID := uuid.New()
		sessionID := uuid.New()

		existingSession := &domain.Session{
			ID:         sessionID,
			Token:      "valid-token",
			UserID:     userID,
			DeviceName: "MacBook Pro",
			IPAddress:  "192.168.1.1",
			UserAgent:  "Mozilla/5.0",
			ExpiresAt:  time.Now().UTC().Add(24 * time.Hour),
			CreatedAt:  time.Now().UTC(),
		}

		expectedErr := errors.New("database error")
		sessionRepoMock.On("FindByID", ctx, sessionID).
			Return(existingSession, nil)
		sessionRepoMock.On("DeleteByID", ctx, sessionID).
			Return(expectedErr)

		// Act
		err := service.DeleteSessionByID(ctx, userID, sessionID)

		// Assert
		require.Error(t, err)
		assert.Contains(t, err.Error(), "delete session by id")
		sessionRepoMock.AssertExpectations(t)
	})
}

func TestDeleteSessionsByUserID(t *testing.T) {
	t.Run("should delete all sessions when currentSession is nil", func(t *testing.T) {
		// Arrange
		service, sessionRepoMock := setupSessionService(t)

		ctx := context.Background()
		userID := uuid.New()

		sessionRepoMock.On("DeleteByUserID", ctx, userID).
			Return(nil)

		// Act
		err := service.DeleteSessionsByUserID(ctx, userID, nil)

		// Assert
		require.NoError(t, err)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should delete all sessions except current when currentSession is provided", func(t *testing.T) {
		// Arrange
		service, sessionRepoMock := setupSessionService(t)

		ctx := context.Background()
		userID := uuid.New()
		currentSessionID := uuid.New()

		sessionRepoMock.On("DeleteByUserExceptID", ctx, userID, currentSessionID).
			Return(nil)

		// Act
		err := service.DeleteSessionsByUserID(ctx, userID, &currentSessionID)

		// Assert
		require.NoError(t, err)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository delete all fails", func(t *testing.T) {
		// Arrange
		service, sessionRepoMock := setupSessionService(t)

		ctx := context.Background()
		userID := uuid.New()

		expectedErr := errors.New("database error")
		sessionRepoMock.On("DeleteByUserID", ctx, userID).
			Return(expectedErr)

		// Act
		err := service.DeleteSessionsByUserID(ctx, userID, nil)

		// Assert
		require.Error(t, err)
		assert.Contains(t, err.Error(), "delete all sessions by user id")
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository delete except fails", func(t *testing.T) {
		// Arrange
		service, sessionRepoMock := setupSessionService(t)

		ctx := context.Background()
		userID := uuid.New()
		currentSessionID := uuid.New()

		expectedErr := errors.New("database error")
		sessionRepoMock.On("DeleteByUserExceptID", ctx, userID, currentSessionID).
			Return(expectedErr)

		// Act
		err := service.DeleteSessionsByUserID(ctx, userID, &currentSessionID)

		// Assert
		require.Error(t, err)
		assert.Contains(t, err.Error(), "delete all sessions by user id")
		sessionRepoMock.AssertExpectations(t)
	})
}

func TestGetSessionsByUserID(t *testing.T) {
	t.Run("should return sessions when user has active sessions", func(t *testing.T) {
		// Arrange
		service, sessionRepoMock := setupSessionService(t)

		ctx := context.Background()
		userID := uuid.New()

		expectedSessions := []domain.Session{
			{
				ID:         uuid.New(),
				Token:      "token-1",
				UserID:     userID,
				DeviceName: "MacBook Pro",
				IPAddress:  "192.168.1.1",
				UserAgent:  "Mozilla/5.0",
				ExpiresAt:  time.Now().UTC().Add(24 * time.Hour),
				CreatedAt:  time.Now().UTC(),
			},
			{
				ID:         uuid.New(),
				Token:      "token-2",
				UserID:     userID,
				DeviceName: "iPhone",
				IPAddress:  "192.168.1.2",
				UserAgent:  "Mobile Safari",
				ExpiresAt:  time.Now().UTC().Add(24 * time.Hour),
				CreatedAt:  time.Now().UTC(),
			},
		}

		sessionRepoMock.On("FindByUserID", ctx, userID).
			Return(expectedSessions, nil)

		// Act
		sessions, err := service.GetSessionsByUserID(ctx, userID)

		// Assert
		require.NoError(t, err)
		assert.NotNil(t, sessions)
		assert.Len(t, sessions, 2)
		assert.Equal(t, expectedSessions[0].ID, sessions[0].ID)
		assert.Equal(t, expectedSessions[1].ID, sessions[1].ID)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return empty slice when user has no sessions", func(t *testing.T) {
		// Arrange
		service, sessionRepoMock := setupSessionService(t)

		ctx := context.Background()
		userID := uuid.New()

		sessionRepoMock.On("FindByUserID", ctx, userID).
			Return(nil, repository.ErrSessionNotFound)

		// Act
		sessions, err := service.GetSessionsByUserID(ctx, userID)

		// Assert
		require.NoError(t, err)
		assert.NotNil(t, sessions)
		assert.Empty(t, sessions)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository fails", func(t *testing.T) {
		// Arrange
		service, sessionRepoMock := setupSessionService(t)

		ctx := context.Background()
		userID := uuid.New()

		expectedErr := errors.New("database connection error")
		sessionRepoMock.On("FindByUserID", ctx, userID).
			Return(nil, expectedErr)

		// Act
		sessions, err := service.GetSessionsByUserID(ctx, userID)

		// Assert
		require.Error(t, err)
		assert.Nil(t, sessions)
		assert.Contains(t, err.Error(), "get user sessions")
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return empty sessions list successfully", func(t *testing.T) {
		// Arrange
		service, sessionRepoMock := setupSessionService(t)

		ctx := context.Background()
		userID := uuid.New()

		emptySessions := []domain.Session{}
		sessionRepoMock.On("FindByUserID", ctx, userID).
			Return(emptySessions, nil)

		// Act
		sessions, err := service.GetSessionsByUserID(ctx, userID)

		// Assert
		require.NoError(t, err)
		assert.NotNil(t, sessions)
		assert.Empty(t, sessions)
		sessionRepoMock.AssertExpectations(t)
	})
}
