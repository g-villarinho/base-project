package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/g-villarinho/base-project/config"
	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/g-villarinho/base-project/internal/repository"
	"github.com/google/uuid"
)

type SessionService interface {
	CreateSession(ctx context.Context, userID uuid.UUID, ipAddress, deviceName, userAgent string) (*domain.Session, error)
	FindSessionByToken(ctx context.Context, token string) (*domain.Session, error)
	DeleteSessionByID(ctx context.Context, userID, sessionID uuid.UUID) error
	DeleteSessionsByUserID(ctx context.Context, userID uuid.UUID, currentSession *uuid.UUID) error
	GetSessionsByUserID(ctx context.Context, userID uuid.UUID) ([]domain.Session, error)
}

type sessionService struct {
	sessionRepo   repository.SessionRepository
	sessionConfig config.Session
	logger        *slog.Logger
}

func NewSessionService(
	sessionRepo repository.SessionRepository,
	config *config.Config,
	logger *slog.Logger) SessionService {
	return &sessionService{
		sessionRepo:   sessionRepo,
		sessionConfig: config.Session,
		logger:        logger.With(slog.String("service", "session")),
	}
}

func (s *sessionService) CreateSession(ctx context.Context, userID uuid.UUID, ipAddress, deviceName, userAgent string) (*domain.Session, error) {
	logger := s.logger.With(
		slog.String("method", "CreateSession"),
		slog.String("user_id", userID.String()),
	)

	expiresAt := time.Now().UTC().Add(s.sessionConfig.Duration)

	session, err := domain.NewSession(userID, ipAddress, userAgent, deviceName, expiresAt)
	if err != nil {
		logger.Error("create session domain", slog.String("error", err.Error()))
		return nil, fmt.Errorf("create session for userID %s: %w", userID, err)
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("create session for userID %s: %w", userID, err)
	}

	return session, nil
}

func (s *sessionService) FindSessionByToken(ctx context.Context, token string) (*domain.Session, error) {
	logger := s.logger.With(
		slog.String("method", "FindSessionByToken"),
	)

	session, err := s.sessionRepo.FindByToken(ctx, token)
	if err != nil {
		if err == repository.ErrSessionNotFound {
			logger.Warn("session not found to proceed", slog.String("token", token))
			return nil, domain.ErrSessionNotFound
		}

		return nil, fmt.Errorf("find session by token: %w", err)
	}

	if session.IsExpired() {
		logger.Warn("session expired", slog.String("session_id", session.ID.String()))
		return nil, domain.ErrSessionExpired
	}

	return session, nil
}

func (s *sessionService) DeleteSessionByID(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID) error {
	logger := s.logger.With(
		slog.String("method", "DeleteSessionByID"),
		slog.String("user_id", userID.String()),
		slog.String("session_id", sessionID.String()),
	)

	session, err := s.sessionRepo.FindByID(ctx, sessionID)
	if err != nil {
		if err == repository.ErrSessionNotFound {
			logger.Warn("session not found to proceed")
			return domain.ErrSessionNotFound
		}

		return fmt.Errorf("find session by id: %w", err)
	}

	if session.UserID != userID {
		logger.Warn("session does not belong to user")
		return domain.ErrSessionNotBelong
	}

	if session.IsExpired() {
		logger.Info("session already expired and not need delete")
		return nil
	}

	if err := s.sessionRepo.DeleteByID(ctx, sessionID); err != nil {
		return fmt.Errorf("delete session by id: %w", err)
	}

	return nil
}

func (s *sessionService) DeleteSessionsByUserID(ctx context.Context, userID uuid.UUID, currentSession *uuid.UUID) error {
	if currentSession == nil {
		if err := s.sessionRepo.DeleteByUserID(ctx, userID); err != nil {
			return fmt.Errorf("delete all sessions by user id: %w", err)
		}

		return nil
	}

	if err := s.sessionRepo.DeleteByUserExceptID(ctx, userID, *currentSession); err != nil {
		return fmt.Errorf("delete all sessions by user id: %w", err)
	}

	return nil
}

func (s *sessionService) GetSessionsByUserID(ctx context.Context, userID uuid.UUID) ([]domain.Session, error) {
	logger := s.logger.With(
		slog.String("method", "GetSessionsByUserID"),
		slog.String("user_id", userID.String()),
	)

	sessions, err := s.sessionRepo.FindByUserID(ctx, userID)
	if err != nil {
		if err == repository.ErrSessionNotFound {
			logger.Info("no sessions found for user")
			return []domain.Session{}, nil
		}

		return nil, fmt.Errorf("get user sessions: %w", err)
	}

	return sessions, nil
}
