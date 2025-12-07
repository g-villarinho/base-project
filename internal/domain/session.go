package domain

import (
	"errors"
	"time"

	"github.com/g-villarinho/base-project/pkg/crypto"
	"github.com/google/uuid"
)

var (
	ErrSessionNotFound  = errors.New("Session not found to perform the operation")
	ErrSessionExpired   = errors.New("Session is expired")
	ErrSessionNotBelong = errors.New("Session does not belong to the user")
)

const (
	defaultSessionTokenSize = 32
)

type Session struct {
	ID         uuid.UUID
	Token      string
	DeviceName string
	IPAddress  string
	UserAgent  string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	UserID     uuid.UUID
	User       User
}

func NewSession(userID uuid.UUID, ipAddress, userAgent, deviceName string, expiresAt time.Time) (*Session, error) {
	token, err := crypto.CreateRandomStringGenerator(defaultSessionTokenSize)
	if err != nil {
		return nil, err
	}

	return &Session{
		ID:         uuid.New(),
		Token:      token,
		DeviceName: deviceName,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		CreatedAt:  time.Now().UTC(),
		UserID:     userID,
		ExpiresAt:  expiresAt,
	}, nil
}

func (s *Session) IsExpired() bool {
	return time.Now().UTC().After(s.ExpiresAt)
}
