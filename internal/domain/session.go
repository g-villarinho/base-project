package domain

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type Session struct {
	ID          uuid.UUID    `gorm:"type:varchar(36);primaryKey"`
	DeviceName  string 		   `gorm:"type:varchar(255);not null"`
	IPAddress   string       `gorm:"type:varchar(45);not null"`
	UserAgent   string       `gorm:"type:text;not null"` 
	ExpiresAt   time.Time    `gorm:"type:datetime;not null;index"`
	CreatedAt   time.Time    `gorm:"type:datetime;not null"`
	RevokedAt   sql.NullTime `gorm:"type:datetime;null;default:null"`

	UserID uuid.UUID `gorm:"type:uuid;not null"`
	User   User      `gorm:"foreignKey:UserID;references:ID;constraint:OnDelete:CASCADE"`	
}

func NewSession(userID uuid.UUID, ipAddress, userAgent, deviceName string, expiresAt time.Time) *Session {
	return &Session{
		ID: uuid.New(),
		DeviceName: deviceName,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		CreatedAt: time.Now().UTC(),
		UserID: userID,
		ExpiresAt: expiresAt,
	}
}

func (s *Session) IsExpired() bool {
	return time.Now().UTC().After(s.ExpiresAt)
}

func (s *Session) IsRevoked() bool {
	return s.RevokedAt.Valid
}
