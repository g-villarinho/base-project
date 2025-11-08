package handler

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/g-villarinho/base-project/internal/server/echoctx"
	"github.com/g-villarinho/base-project/internal/server/model"
	"github.com/g-villarinho/base-project/internal/service"
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
	logger *slog.Logger,
) *SessionHandler {
	return &SessionHandler{
		sessionService: sessionService,
		cookieHandler:  cookieHandler,
		logger:         logger.With(slog.String("handler", "session")),
	}
}

func (h *SessionHandler) RevokeSession(c echo.Context) error {
	logger := h.logger.With(
		slog.String("func", "RevokeSession"),
		slog.String("user_id", echoctx.GetUserID(c).String()),
		slog.String("session_id", echoctx.GetSessionID(c).String()),
	)

	sessionId, err := uuid.Parse(c.Param("session_id"))
	if err != nil {
		logger.Warn("invalid session_id param", slog.String("param", c.Param("session_id")))
		return BadRequest(c, "invalid session_id parameter")
	}

	if err := h.sessionService.DeleteSessionByID(c.Request().Context(), echoctx.GetUserID(c), sessionId); err != nil {
		if errors.Is(err, domain.ErrSessionNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}

		if errors.Is(err, domain.ErrSessionNotBelong) {
			return echo.NewHTTPError(http.StatusForbidden, err.Error())
		}

		return echo.ErrInternalServerError
	}

	if sessionId == echoctx.GetSessionID(c) {
		h.cookieHandler.Delete(c)
	}

	return c.NoContent(http.StatusNoContent)
}

func (h *SessionHandler) RevokeAllSessions(c echo.Context) error {
	logger := h.logger.With(
		slog.String("func", "RevokeAllSessions"),
		slog.String("user_id", echoctx.GetUserID(c).String()),
		slog.String("session_id", echoctx.GetSessionID(c).String()),
	)

	var payload model.RevokeAllSessionsPayload
	if err := c.Bind(&payload); err != nil {
		logger.Warn("bind payload", slog.Any("error", err))
		return BadRequest(c, "Invalid request payload. please check the submitted data.")
	}

	var currentSessionId *uuid.UUID
	if payload.IncludeCurrent {
		sessionID := echoctx.GetSessionID(c)
		currentSessionId = &sessionID
	}

	if err := h.sessionService.DeleteSessionsByUserID(c.Request().Context(), echoctx.GetUserID(c), currentSessionId); err != nil {
		return InternalServerError(c, "failed to revoke all sessions")
	}

	if payload.IncludeCurrent {
		h.cookieHandler.Delete(c)
	}

	return c.NoContent(http.StatusNoContent)
}
