package domain

import (
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidVerificationToken        = errors.New("Invalid or expired verification token")
	ErrVerificationTokenNotFound       = errors.New("Verification token does not exists")
	ErrInvalidVerificationTokenPayload = errors.New("Invalid verification token payload")
)

type VerificationTokenFlow string

const (
	ResetPasswordFlow     VerificationTokenFlow = "RESET_PASSWORD"
	VerificationEmailFlow VerificationTokenFlow = "VERIFICATION_EMAIL"
	ChangeEmailFlow       VerificationTokenFlow = "CHANGE_EMAIL"
)

type VerificationToken struct {
	ID        uuid.UUID             `gorm:"type:varchar(36);primaryKey"`
	Flow      VerificationTokenFlow `gorm:"type:varchar(20);not null;check:flow IN ('RESET_PASSWORD','VERIFICATION_EMAIL', 'CHANGE_EMAIL')"`
	CreatedAt time.Time             `gorm:"type:datetime;not null"`
	ExpiresAt time.Time             `gorm:"type:datetime;not null;index"`
	Payload   sql.NullString        `gorm:"type:text"`

	UserID uuid.UUID `gorm:"type:uuid;not null"`
	User   User      `gorm:"foreignKey:UserID;references:ID;constraint:OnDelete:CASCADE"`
}

func NewVerificationCode(userID uuid.UUID, flow VerificationTokenFlow, expiresAt time.Time, payload string) *VerificationToken {
	return &VerificationToken{
		ID:        uuid.New(),
		Flow:      flow,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
		UserID:    userID,
		Payload:   sql.NullString{String: payload, Valid: payload != ""},
	}
}

func (vt *VerificationToken) IsVerificationEmailFlow() bool {
	return vt.Flow == VerificationEmailFlow
}

func (vt *VerificationToken) IsResetPasswordFlow() bool {
	return vt.Flow == ResetPasswordFlow
}

func (vt *VerificationToken) IsChangeEmailFlow() bool {
	return vt.Flow == ChangeEmailFlow
}

func (vt *VerificationToken) IsExpired() bool {
	return time.Now().UTC().After(vt.ExpiresAt)
}
