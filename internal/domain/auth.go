package domain

import (
	"time"

	"github.com/google/uuid"
)

type LoginResult struct {
	SessionToken     string
	SessionExpiresAt time.Time
	UserID           uuid.UUID
}
