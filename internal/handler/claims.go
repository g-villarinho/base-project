package handler

import (
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type ClaimsKey string

const (
	UserIDKey ClaimsKey = "user_id"
	TokenKey  ClaimsKey = "email"
)

func SetUserID(c echo.Context, userID uuid.UUID) {
	c.Set(string(UserIDKey), userID)
}

func GetUserID(c echo.Context) uuid.UUID {
	return c.Get(string(UserIDKey)).(uuid.UUID)
}
