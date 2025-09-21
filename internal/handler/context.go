package handler

import (
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type ContextKey string

const (
	userIDKey    ContextKey = "user_id"
	sessionIDKey ContextKey = "session_id"
)

func SetUserID(c echo.Context, userID uuid.UUID) {
	c.Set(string(userIDKey), userID)
}

func GetUserID(c echo.Context) uuid.UUID {
	return c.Get(string(userIDKey)).(uuid.UUID)
}

func SetSessionID(c echo.Context, sessionID uuid.UUID) {
	c.Set(string(sessionIDKey), sessionID)
}

func GetSessionID(c echo.Context) uuid.UUID {
	return c.Get(string(sessionIDKey)).(uuid.UUID)
}
