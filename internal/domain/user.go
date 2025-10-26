package domain

import (
	"database/sql"
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
	ID               uuid.UUID    `gorm:"type:varchar(36);primaryKey"`
	Name             string       `gorm:"type:varchar(155);not null"`
	Email            string       `gorm:"type:varchar(155);not null;unique;index"`
	Status           UserStatus   `gorm:"type:varchar(20);not null;default:'PENDING';check:status IN ('PENDING','ACTIVE','BLOCKED')"`
	PasswordHash     string       `gorm:"type:varchar(255);not null"`
	CreatedAt        time.Time    `gorm:"type:datetime;not null"`
	UpdatedAt        sql.NullTime `gorm:"type:datetime;null;default:null"`
	EmailConfirmedAt sql.NullTime `gorm:"type:datetime;null;default:null"`
	BlockedAt        sql.NullTime `gorm:"type:datetime;null;default:null"`
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
	return u.EmailConfirmedAt.Valid
}
