package middleware

import (
	"log/slog"

	"github.com/g-villarinho/base-project/internal/server/echoctx"
	"github.com/g-villarinho/base-project/internal/server/handler"
	"github.com/g-villarinho/base-project/internal/service"
	"github.com/labstack/echo/v4"
)

type AuthMiddleware struct {
	logger         *slog.Logger
	cookieHandler  handler.CookieHandler
	sessionService service.SessionService
}

func NewAuthMiddleware(
	logger *slog.Logger,
	cookieHandler handler.CookieHandler,
	sessionService service.SessionService) *AuthMiddleware {
	return &AuthMiddleware{
		logger:         logger.With(slog.String("middleware", "auth")),
		cookieHandler:  cookieHandler,
		sessionService: sessionService,
	}
}

func (m *AuthMiddleware) EnsuredAuthenticated(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		logger := m.logger.With(
			slog.String("method", "EnsuredAuthenticated"),
			slog.String("path", c.Request().URL.Path),
		)

		cookie, err := m.cookieHandler.Get(c)
		if err != nil {
			logger.Warn("authentication failed: unable to retrieve cookie", slog.Any("error", err))
			return handler.Unauthorized(c, "TOKEN_MISSING", "You need to be logged in to access this resource.")
		}

		session, err := m.sessionService.FindSessionByToken(c.Request().Context(), cookie.Value)
		if err != nil {
			logger.Warn("authentication failed: invalid session token", slog.Any("error", err))
			m.cookieHandler.Delete(c)
			return handler.Unauthorized(c, "TOKEN_EXPIRED", "Your session has expired. Please log in again.")
		}

		echoctx.SetUserID(c, session.UserID)
		echoctx.SetSessionID(c, session.ID)
		return next(c)
	}
}
