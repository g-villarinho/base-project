package handler

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/g-villarinho/user-demo/internal/domain"
	"github.com/g-villarinho/user-demo/internal/model"
	"github.com/g-villarinho/user-demo/internal/service"
	"github.com/google/uuid"
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
	logger := h.logger.With(
		slog.String("method", "RevokeSession"),
		slog.String("path", c.Request().URL.Path),
	)

	sessionId, err := uuid.Parse(c.Param("session_id"))
	if err != nil {
		return echo.ErrBadRequest
	}

	if err := h.sessionService.DeleteSessionByID(c.Request().Context(), GetUserID(c), sessionId); err != nil {
		logger.Error("failed to revoke session", slog.String("session_id", sessionId.String()), slog.String("error", err.Error()))
		if errors.Is(err, domain.ErrSessionNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}

		if errors.Is(err, domain.ErrSessionNotBelong) {
			return echo.NewHTTPError(http.StatusForbidden, err.Error())
		}

		return echo.ErrInternalServerError
	}

	if sessionId == GetSessionID(c) {
		h.cookieHandler.Delete(c)
	}

	return c.NoContent(http.StatusNoContent)
}

func (h *SessionHandler) RevokeAllSessions(c echo.Context) error {
	logger := h.logger.With(
		slog.String("method", "RevokeAllSessions"),
		slog.String("path", c.Request().URL.Path),
	)

	var payload model.RevokeAllSessionsPayload
	if err := c.Bind(&payload); err != nil {
		logger.Error("bind request body", "error", err)
		return echo.ErrBadRequest
	}

	var currentSessionId *uuid.UUID
	if payload.IncludeCurrent {
		sessionID := GetSessionID(c)
		currentSessionId = &sessionID
	}

	if err := h.sessionService.DeleteSessionsByUserID(c.Request().Context(), GetUserID(c), currentSessionId); err != nil {
		logger.Error("failed to revoke all sessions", slog.String("error", err.Error()))
		return echo.ErrInternalServerError
	}

	if payload.IncludeCurrent {
		h.cookieHandler.Delete(c)
	}

	return c.NoContent(http.StatusNoContent)
}
