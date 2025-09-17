package model

import "time"

type AccessToken struct {
	Value     string
	ExpiresAt time.Time
}
