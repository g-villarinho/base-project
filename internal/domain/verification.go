package domain

import (
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
	Payload   *string
	UserID    uuid.UUID
	User      User
}

func NewVerification(userID uuid.UUID, flow VerificationFlow, expiresAt time.Time, payload string) (*Verification, error) {
	token, err := crypto.CreateRandomStringGenerator(32)
	if err != nil {
		return nil, err
	}

	var payloadPtr *string
	if payload != "" {
		payloadPtr = &payload
	}

	return &Verification{
		ID:        uuid.New(),
		Flow:      flow,
		Token:     token,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
		UserID:    userID,
		Payload:   payloadPtr,
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
