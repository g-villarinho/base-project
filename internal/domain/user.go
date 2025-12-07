package domain

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrEmailAlreadyExists   = errors.New("a user with this email already exists")
	ErrInvalidCredentials   = errors.New("email or password invalid")
	ErrUserBlocked          = errors.New("account has been temporarily blocked")
	ErrEmailNotVerified     = errors.New("email not verified")
	ErrEmailAlreadyVerified = errors.New("email is already verified")
	ErrUserNotFound         = errors.New("user not found to perform this operation")
	ErrPasswordMismatch     = errors.New("current password does not match")
	ErrEmailInUse           = errors.New("the new email is already in use by another account")
	ErrEmailIsTheSame       = errors.New("the new email must be different from the current email")
)

type UserStatus string

var (
	PendingStatus UserStatus = "PENDING"
	ActiveStatus  UserStatus = "ACTIVE"
	BlockedStatus UserStatus = "BLOCKED"
)

type User struct {
	ID               uuid.UUID
	Name             string
	Email            string
	Status           UserStatus
	PasswordHash     string
	CreatedAt        time.Time
	UpdatedAt        *time.Time
	EmailConfirmedAt *time.Time
	BlockedAt        *time.Time
}

func NewUser(name, email, passwordHash string) *User {
	return &User{
		ID:           uuid.New(),
		Name:         name,
		Email:        email,
		Status:       PendingStatus,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now().UTC(),
	}
}

func (u *User) IsBlocked() bool {
	return u.Status == BlockedStatus
}

func (u *User) IsEmailVerified() bool {
	return u.EmailConfirmedAt != nil
}
