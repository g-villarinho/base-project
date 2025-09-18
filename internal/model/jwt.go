package model

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AccessToken struct {
	Value     string
	ExpiresAt time.Time
}

type CustomClaims struct {
	jwt.RegisteredClaims
	SessionID string `json:"sid"`
}
