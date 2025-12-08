package handler

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/g-villarinho/base-project/internal/api/echoctx"
	"github.com/g-villarinho/base-project/internal/api/model"
	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/g-villarinho/base-project/internal/service"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
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

// RevokeSession godoc
// @Summary      Revoke specific session
// @Description  Revokes a specific session by ID (must belong to authenticated user)
// @Tags         Sessions
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Param        session_id  path      string  true  "Session ID (UUID)"
// @Success      204  "Session revoked successfully"
// @Failure      400  {object}  model.ProblemJSON  "Invalid session ID format"
// @Failure      401  {object}  model.ProblemJSON  "Unauthorized - authentication required"
// @Failure      403  {object}  model.ProblemJSON  "Session does not belong to user"
// @Failure      404  {object}  model.ProblemJSON  "Session not found"
// @Failure      500  {object}  model.ProblemJSON  "Internal server error"
// @Router       /sessions/{session_id} [delete]
func (h *SessionHandler) RevokeSession(c echo.Context) error {
	logger := h.logger.With(
		slog.String("func", "RevokeSession"),
		slog.String("user_id", echoctx.GetUserID(c).String()),
		slog.String("session_id", echoctx.GetSessionID(c).String()),
	)

	sessionId, err := uuid.Parse(c.Param("session_id"))
	if err != nil {
		logger.Warn("invalid session_id param", slog.String("param", c.Param("session_id")))
		return BadRequest(c, "INVALID_SESSION_ID", "invalid session_id parameter")
	}

	if err := h.sessionService.DeleteSessionByID(c.Request().Context(), echoctx.GetUserID(c), sessionId); err != nil {
		if errors.Is(err, domain.ErrSessionNotFound) {
			logger.Warn("cannot revoke session: not found", slog.String("session_id_param", sessionId.String()))
			return NotFound(c, "SESSION_NOT_FOUND", err.Error())
		}

		if errors.Is(err, domain.ErrSessionNotBelong) {
			logger.Warn("the session does not belong to the user", slog.String("session_id_param", sessionId.String()))
			return Forbidden(c, "FORBIDDEN_SESSION", "you do not have permission to revoke this session")
		}

		log.Error("revoke session", slog.Any("error", err))
		return echo.ErrInternalServerError
	}

	if sessionId == echoctx.GetSessionID(c) {
		h.cookieHandler.Delete(c)
	}

	return c.NoContent(http.StatusNoContent)
}

// RevokeAllSessions godoc
// @Summary      Revoke all sessions
// @Description  Revokes all sessions for the authenticated user (optionally including current session)
// @Tags         Sessions
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Param        payload  body      model.RevokeAllSessionsPayload  true  "Include current session flag"
// @Success      204  "All sessions revoked successfully"
// @Failure      401  {object}  model.ProblemJSON  "Unauthorized - authentication required"
// @Failure      500  {object}  model.ProblemJSON  "Internal server error"
// @Router       /sessions [delete]
func (h *SessionHandler) RevokeAllSessions(c echo.Context) error {
	logger := h.logger.With(
		slog.String("func", "RevokeAllSessions"),
		slog.String("user_id", echoctx.GetUserID(c).String()),
		slog.String("session_id", echoctx.GetSessionID(c).String()),
	)

	var payload model.RevokeAllSessionsPayload
	if err := c.Bind(&payload); err != nil {
		logger.Warn("bind payload", slog.Any("error", err))
		return InvalidBind(c)
	}

	var currentSessionId *uuid.UUID
	if payload.IncludeCurrent {
		sessionID := echoctx.GetSessionID(c)
		currentSessionId = &sessionID
	}

	if err := h.sessionService.DeleteSessionsByUserID(c.Request().Context(), echoctx.GetUserID(c), currentSessionId); err != nil {
		log.Error("revoke all sessions", slog.Any("error", err))
		return InternalServerError(c, "failed to revoke all sessions")
	}

	if payload.IncludeCurrent {
		h.cookieHandler.Delete(c)
	}

	return c.NoContent(http.StatusNoContent)
}
