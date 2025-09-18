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
	sessionRepo repository.SessionRepository
	securityConfig config.Security
}

func NewSessionService(sessionRepo repository.SessionRepository, config config.Config) SessionService {
	return &sessionService{
		sessionRepo: sessionRepo,
		securityConfig: config.Security,
	}
}

func (s *sessionService) CreateSession(ctx context.Context, userID uuid.UUID, ipAddress, deviceName, userAgent string) (*domain.Session, error) {
	expiresAt := time.Now().UTC().Add(s.securityConfig.AccessTokenExpirationHours)

	session := domain.NewSession(userID, ipAddress, userAgent, deviceName, expiresAt) 

	if err := s.sessionRepo.Create(ctx, session); err != nil {
    return nil, fmt.Errorf("create session for userID %s: %w", userID, err)
	} 

	return session, nil
}


