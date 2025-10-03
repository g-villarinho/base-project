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

func TestSessionService_CreateSession(t *testing.T) {
	t.Run("should create session successfully when all parameters are valid", func(t *testing.T) {
		service, sessionRepoMock := setupSessionService(t)
		ctx := context.Background()
		userID := uuid.New()
		ipAddress := "192.168.1.1"
		deviceName := "Chrome on Windows"
		userAgent := "Mozilla/5.0"

		sessionRepoMock.On("Create", ctx, mock.AnythingOfType("*domain.Session")).Return(nil)

		session, err := service.CreateSession(ctx, userID, ipAddress, deviceName, userAgent)

		assert.NoError(t, err)
		assert.NotNil(t, session)
		assert.Equal(t, userID, session.UserID)
		assert.Equal(t, ipAddress, session.IPAddress)
		assert.Equal(t, deviceName, session.DeviceName)
		assert.Equal(t, userAgent, session.UserAgent)
		assert.NotEmpty(t, session.Token)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository fails to create session", func(t *testing.T) {
		service, sessionRepoMock := setupSessionService(t)
		ctx := context.Background()
		userID := uuid.New()
		repoErr := errors.New("database error")

		sessionRepoMock.On("Create", ctx, mock.AnythingOfType("*domain.Session")).Return(repoErr)

		session, err := service.CreateSession(ctx, userID, "192.168.1.1", "Device", "UserAgent")

		assert.Error(t, err)
		assert.Nil(t, session)
		sessionRepoMock.AssertExpectations(t)
	})
}

func TestSessionService_FindSessionByToken(t *testing.T) {
	t.Run("should return session when token is valid and not expired", func(t *testing.T) {
		service, sessionRepoMock := setupSessionService(t)
		ctx := context.Background()
		token := "valid-token"
		expectedSession := &domain.Session{
			ID:         uuid.New(),
			Token:      token,
			UserID:     uuid.New(),
			ExpiresAt:  time.Now().UTC().Add(1 * time.Hour),
			IPAddress:  "192.168.1.1",
			DeviceName: "Device",
			UserAgent:  "UserAgent",
		}

		sessionRepoMock.On("FindByToken", ctx, token).Return(expectedSession, nil)

		session, err := service.FindSessionByToken(ctx, token)

		assert.NoError(t, err)
		assert.Equal(t, expectedSession, session)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return domain error when session is not found", func(t *testing.T) {
		service, sessionRepoMock := setupSessionService(t)
		ctx := context.Background()
		token := "invalid-token"

		sessionRepoMock.On("FindByToken", ctx, token).Return(nil, repository.ErrSessionNotFound)

		session, err := service.FindSessionByToken(ctx, token)

		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Equal(t, domain.ErrSessionNotFound, err)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return domain error when session is expired", func(t *testing.T) {
		service, sessionRepoMock := setupSessionService(t)
		ctx := context.Background()
		token := "expired-token"
		expiredSession := &domain.Session{
			ID:        uuid.New(),
			Token:     token,
			UserID:    uuid.New(),
			ExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
		}

		sessionRepoMock.On("FindByToken", ctx, token).Return(expiredSession, nil)

		session, err := service.FindSessionByToken(ctx, token)

		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Equal(t, domain.ErrSessionExpired, err)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository fails", func(t *testing.T) {
		service, sessionRepoMock := setupSessionService(t)
		ctx := context.Background()
		token := "some-token"
		repoErr := errors.New("database connection failed")

		sessionRepoMock.On("FindByToken", ctx, token).Return(nil, repoErr)

		session, err := service.FindSessionByToken(ctx, token)

		assert.Error(t, err)
		assert.Nil(t, session)
		assert.NotEqual(t, domain.ErrSessionNotFound, err)
		sessionRepoMock.AssertExpectations(t)
	})
}

func TestSessionService_DeleteSessionByID(t *testing.T) {
	t.Run("should delete session successfully when session belongs to user", func(t *testing.T) {
		service, sessionRepoMock := setupSessionService(t)
		ctx := context.Background()
		userID := uuid.New()
		sessionID := uuid.New()
		session := &domain.Session{
			ID:     sessionID,
			UserID: userID,
		}

		sessionRepoMock.On("FindByID", ctx, sessionID).Return(session, nil)
		sessionRepoMock.On("DeleteByID", ctx, sessionID).Return(nil)

		err := service.DeleteSessionByID(ctx, userID, sessionID)

		assert.NoError(t, err)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return domain error when session is not found", func(t *testing.T) {
		service, sessionRepoMock := setupSessionService(t)
		ctx := context.Background()
		userID := uuid.New()
		sessionID := uuid.New()

		sessionRepoMock.On("FindByID", ctx, sessionID).Return(nil, repository.ErrSessionNotFound)

		err := service.DeleteSessionByID(ctx, userID, sessionID)

		assert.Error(t, err)
		assert.Equal(t, domain.ErrSessionNotFound, err)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return domain error when session does not belong to user", func(t *testing.T) {
		service, sessionRepoMock := setupSessionService(t)
		ctx := context.Background()
		userID := uuid.New()
		differentUserID := uuid.New()
		sessionID := uuid.New()
		session := &domain.Session{
			ID:     sessionID,
			UserID: differentUserID,
		}

		sessionRepoMock.On("FindByID", ctx, sessionID).Return(session, nil)

		err := service.DeleteSessionByID(ctx, userID, sessionID)

		assert.Error(t, err)
		assert.Equal(t, domain.ErrSessionNotBelong, err)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository fails to find session", func(t *testing.T) {
		service, sessionRepoMock := setupSessionService(t)
		ctx := context.Background()
		userID := uuid.New()
		sessionID := uuid.New()
		repoErr := errors.New("database error")

		sessionRepoMock.On("FindByID", ctx, sessionID).Return(nil, repoErr)

		err := service.DeleteSessionByID(ctx, userID, sessionID)

		assert.Error(t, err)
		assert.NotEqual(t, domain.ErrSessionNotFound, err)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository fails to delete session", func(t *testing.T) {
		service, sessionRepoMock := setupSessionService(t)
		ctx := context.Background()
		userID := uuid.New()
		sessionID := uuid.New()
		session := &domain.Session{
			ID:     sessionID,
			UserID: userID,
		}
		repoErr := errors.New("delete failed")

		sessionRepoMock.On("FindByID", ctx, sessionID).Return(session, nil)
		sessionRepoMock.On("DeleteByID", ctx, sessionID).Return(repoErr)

		err := service.DeleteSessionByID(ctx, userID, sessionID)

		assert.Error(t, err)
		sessionRepoMock.AssertExpectations(t)
	})
}

func TestSessionService_DeleteSessionsByUserID(t *testing.T) {
	t.Run("should delete all sessions when current session is nil", func(t *testing.T) {
		service, sessionRepoMock := setupSessionService(t)
		ctx := context.Background()
		userID := uuid.New()

		sessionRepoMock.On("DeleteByUserID", ctx, userID).Return(nil)

		err := service.DeleteSessionsByUserID(ctx, userID, nil)

		assert.NoError(t, err)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should delete all sessions except current when current session is provided", func(t *testing.T) {
		service, sessionRepoMock := setupSessionService(t)
		ctx := context.Background()
		userID := uuid.New()
		currentSessionID := uuid.New()

		sessionRepoMock.On("DeleteByUserExceptID", ctx, userID, currentSessionID).Return(nil)

		err := service.DeleteSessionsByUserID(ctx, userID, &currentSessionID)

		assert.NoError(t, err)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository fails to delete all sessions", func(t *testing.T) {
		service, sessionRepoMock := setupSessionService(t)
		ctx := context.Background()
		userID := uuid.New()
		repoErr := errors.New("delete failed")

		sessionRepoMock.On("DeleteByUserID", ctx, userID).Return(repoErr)

		err := service.DeleteSessionsByUserID(ctx, userID, nil)

		assert.Error(t, err)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository fails to delete sessions except current", func(t *testing.T) {
		service, sessionRepoMock := setupSessionService(t)
		ctx := context.Background()
		userID := uuid.New()
		currentSessionID := uuid.New()
		repoErr := errors.New("delete failed")

		sessionRepoMock.On("DeleteByUserExceptID", ctx, userID, currentSessionID).Return(repoErr)

		err := service.DeleteSessionsByUserID(ctx, userID, &currentSessionID)

		assert.Error(t, err)
		sessionRepoMock.AssertExpectations(t)
	})
}

func TestSessionService_GetSessionsByUserID(t *testing.T) {
	t.Run("should return sessions when user has sessions", func(t *testing.T) {
		service, sessionRepoMock := setupSessionService(t)
		ctx := context.Background()
		userID := uuid.New()
		expectedSessions := []domain.Session{
			{
				ID:         uuid.New(),
				UserID:     userID,
				Token:      "token1",
				IPAddress:  "192.168.1.1",
				DeviceName: "Device1",
				UserAgent:  "UserAgent1",
			},
			{
				ID:         uuid.New(),
				UserID:     userID,
				Token:      "token2",
				IPAddress:  "192.168.1.2",
				DeviceName: "Device2",
				UserAgent:  "UserAgent2",
			},
		}

		sessionRepoMock.On("FindByUserID", ctx, userID).Return(expectedSessions, nil)

		sessions, err := service.GetSessionsByUserID(ctx, userID)

		assert.NoError(t, err)
		assert.Equal(t, expectedSessions, sessions)
		assert.Len(t, sessions, 2)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return empty slice when no sessions are found", func(t *testing.T) {
		service, sessionRepoMock := setupSessionService(t)
		ctx := context.Background()
		userID := uuid.New()

		sessionRepoMock.On("FindByUserID", ctx, userID).Return(nil, repository.ErrSessionNotFound)

		sessions, err := service.GetSessionsByUserID(ctx, userID)

		assert.NoError(t, err)
		assert.Empty(t, sessions)
		sessionRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository fails", func(t *testing.T) {
		service, sessionRepoMock := setupSessionService(t)
		ctx := context.Background()
		userID := uuid.New()
		repoErr := errors.New("database connection failed")

		sessionRepoMock.On("FindByUserID", ctx, userID).Return(nil, repoErr)

		sessions, err := service.GetSessionsByUserID(ctx, userID)

		assert.Error(t, err)
		assert.Nil(t, sessions)
		sessionRepoMock.AssertExpectations(t)
	})
}
