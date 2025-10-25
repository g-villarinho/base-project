package handler

import (
	"errors"
	"net/http"

	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/g-villarinho/base-project/internal/echoctx"
	"github.com/g-villarinho/base-project/internal/model"
	"github.com/g-villarinho/base-project/internal/service"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type SessionHandler struct {
	sessionService service.SessionService
	cookieHandler  CookieHandler
}

func NewSessionHandler(
	sessionService service.SessionService,
	cookieHandler CookieHandler) *SessionHandler {
	return &SessionHandler{
		sessionService: sessionService,
		cookieHandler:  cookieHandler,
	}
}

func (h *SessionHandler) RevokeSession(c echo.Context) error {
	sessionId, err := uuid.Parse(c.Param("session_id"))
	if err != nil {
		return echo.ErrBadRequest
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
	var payload model.RevokeAllSessionsPayload
	if err := c.Bind(&payload); err != nil {
		return echo.ErrBadRequest
	}

	var currentSessionId *uuid.UUID
	if payload.IncludeCurrent {
		sessionID := echoctx.GetSessionID(c)
		currentSessionId = &sessionID
	}

	if err := h.sessionService.DeleteSessionsByUserID(c.Request().Context(), echoctx.GetUserID(c), currentSessionId); err != nil {
		return echo.ErrInternalServerError
	}

	if payload.IncludeCurrent {
		h.cookieHandler.Delete(c)
	}

	return c.NoContent(http.StatusNoContent)
}
