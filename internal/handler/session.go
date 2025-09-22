package handler

import (
	"log/slog"
	"net/http"

	"github.com/g-villarinho/user-demo/internal/service"
	"github.com/labstack/echo/v4"
)

type SessionHandler struct {
	sessionService service.SessionService
	cookieHandler  CookieHandler
	logger         *slog.Logger
}

func NewSessionHandler(
	sessionService service.SessionService,
	cookieHandler CookieHandler,
	logger *slog.Logger) *SessionHandler {
	return &SessionHandler{
		sessionService: sessionService,
		cookieHandler:  cookieHandler,
		logger:         logger.With(slog.String("handler", "session")),
	}
}

func (h *SessionHandler) RevokeSession(c echo.Context) error {
	// logger := h.logger.With(
	// 	slog.String("method", "RevokeSession"),
	// 	slog.String("path", c.Request().URL.Path),
	// )

	// sessionId, err := uuid.Parse(c.Param("session_id"))
	// if err != nil {
	// 	return echo.ErrBadRequest
	// }

	return c.NoContent(http.StatusNoContent)
}
