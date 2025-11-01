package echoctx

import (
	"github.com/g-villarinho/base-project/internal/model"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type ContextKey string

const (
	userIDKey     ContextKey = "user_id"
	sessionIDKey  ContextKey = "session_id"
	clientInfoKey ContextKey = "client_info"
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

func SetClientInfo(c echo.Context, clientInfo model.ClientInfo) {
	c.Set(string(clientInfoKey), clientInfo)
}

func GetClientInfo(c echo.Context) model.ClientInfo {
	return c.Get(string(clientInfoKey)).(model.ClientInfo)
}
