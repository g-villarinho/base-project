package service

import (
	"context"
	"fmt"
	"time"

	"github.com/g-villarinho/user-demo/config"
	"github.com/g-villarinho/user-demo/internal/domain"
	"github.com/g-villarinho/user-demo/internal/repository"
	"github.com/google/uuid"
)

type SessionService interface {
	CreateSession(ctx context.Context, userID uuid.UUID, ipAddress, deviceName, userAgent string) (*domain.Session, error)
	FindSessionByToken(ctx context.Context, token string) (*domain.Session, error)
	DeleteSessionByID(ctx context.Context, userID, sessionID uuid.UUID) error
	DeleteSessionsByUserID(ctx context.Context, userID uuid.UUID, currentSession *uuid.UUID) error
}

type sessionService struct {
	sessionRepo   repository.SessionRepository
	sessionConfig config.Session
}

func NewSessionService(
	sessionRepo repository.SessionRepository,
	config *config.Config) SessionService {
	return &sessionService{
		sessionRepo:   sessionRepo,
		sessionConfig: config.Session,
	}
}

func (s *sessionService) CreateSession(ctx context.Context, userID uuid.UUID, ipAddress, deviceName, userAgent string) (*domain.Session, error) {
	expiresAt := time.Now().UTC().Add(s.sessionConfig.Duration)

	session, err := domain.NewSession(userID, ipAddress, userAgent, deviceName, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("create session for userID %s: %w", userID, err)
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("create session for userID %s: %w", userID, err)
	}

	return session, nil
}

func (s *sessionService) FindSessionByToken(ctx context.Context, token string) (*domain.Session, error) {
	session, err := s.sessionRepo.FindByToken(ctx, token)
	if err != nil {
		if err == repository.ErrSessionNotFound {
			return nil, domain.ErrSessionNotFound
		}

		return nil, fmt.Errorf("find session by token: %w", err)
	}

	if session.IsExpired() {
		return nil, domain.ErrSessionExpired
	}

	return session, nil
}

func (s *sessionService) DeleteSessionByID(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID) error {
	session, err := s.sessionRepo.FindByID(ctx, sessionID)
	if err != nil {
		if err == repository.ErrSessionNotFound {
			return domain.ErrSessionNotFound
		}

		return fmt.Errorf("find session by id: %w", err)
	}

	if session.UserID != userID {
		return domain.ErrSessionNotBelong
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
