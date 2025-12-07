package domain

import (
	"database/sql"
	"errors"
	"time"

	"github.com/g-villarinho/base-project/pkg/crypto"
	"github.com/google/uuid"
)

var (
	ErrInvalidVerification        = errors.New("invalid or expired verification")
	ErrVerificationNotFound       = errors.New("verification does not exists")
	ErrInvalidVerificationPayload = errors.New("invalid verification payload")
)

type VerificationFlow string

const (
	ResetPasswordFlow     VerificationFlow = "RESET_PASSWORD"
	VerificationEmailFlow VerificationFlow = "VERIFICATION_EMAIL"
	ChangeEmailFlow       VerificationFlow = "CHANGE_EMAIL"
)

type Verification struct {
	ID        uuid.UUID
	Flow      VerificationFlow
	Token     string
	CreatedAt time.Time
	ExpiresAt time.Time
	Payload   sql.NullString
	UserID    uuid.UUID
	User      User
}

func NewVerification(userID uuid.UUID, flow VerificationFlow, expiresAt time.Time, payload string) (*Verification, error) {
	token, err := crypto.CreateRandomStringGenerator(32)
	if err != nil {
		return nil, err
	}

	return &Verification{
		ID:        uuid.New(),
		Flow:      flow,
		Token:     token,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
		UserID:    userID,
		Payload:   sql.NullString{String: payload, Valid: payload != ""},
	}, nil
}

func (vt *Verification) IsVerificationEmailFlow() bool {
	return vt.Flow == VerificationEmailFlow
}

func (vt *Verification) IsResetPasswordFlow() bool {
	return vt.Flow == ResetPasswordFlow
}

func (vt *Verification) IsChangeEmailFlow() bool {
	return vt.Flow == ChangeEmailFlow
}

func (vt *Verification) IsExpired() bool {
	return time.Now().UTC().After(vt.ExpiresAt)
}
