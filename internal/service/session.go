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
}

type sessionService struct {
	sessionRepo   repository.SessionRepository
	sessionConfig config.Session
}

func NewSessionService(
	sessionRepo repository.SessionRepository,
	config config.Config) SessionService {
	return &sessionService{
		sessionRepo:   sessionRepo,
		sessionConfig: config.Session,
	}
}

func (s *sessionService) CreateSession(ctx context.Context, userID uuid.UUID, ipAddress, deviceName, userAgent string) (*domain.Session, error) {
	expiresAt := time.Now().UTC().Add(s.sessionConfig.Duration)

	session := domain.NewSession(userID, ipAddress, userAgent, deviceName, expiresAt)

	session.GenerateToken(s.sessionConfig.TokenSize)

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("create session for userID %s: %w", userID, err)
	}

	return session, nil
}
