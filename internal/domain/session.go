package domain

import (
	"errors"
	"time"

	"github.com/g-villarinho/user-demo/pkg/crypto"
	"github.com/google/uuid"
)

var (
	ErrSessionNotFound = errors.New("Session not found to perform the operation")
	ErrSessionExpired  = errors.New("Session is expired")
)

const (
	defaultSessionTokenSize = 32
)

type Session struct {
	ID         uuid.UUID `gorm:"type:varchar(36);primaryKey"`
	Token      string    `gorm:"type:varchar(255);not null;uniqueIndex"`
	DeviceName string    `gorm:"type:varchar(255);not null"`
	IPAddress  string    `gorm:"type:varchar(45);not null"`
	UserAgent  string    `gorm:"type:text;not null"`
	ExpiresAt  time.Time `gorm:"type:datetime;not null;index"`
	CreatedAt  time.Time `gorm:"type:datetime;not null"`

	UserID uuid.UUID `gorm:"type:uuid;not null"`
	User   User      `gorm:"foreignKey:UserID;references:ID;constraint:OnDelete:CASCADE"`
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
