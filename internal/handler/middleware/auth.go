package middleware

import (
	"log/slog"

	"github.com/g-villarinho/user-demo/internal/handler"
	"github.com/g-villarinho/user-demo/internal/service"
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
			logger.Warn("authentication failed: no cookie found")
			return echo.ErrUnauthorized
		}

		if cookie.Value == "" {
			logger.Warn("authentication failed: empty cookie value")
			m.cookieHandler.Delete(c)
			return echo.ErrUnauthorized
		}

		session, err := m.sessionService.FindSessionByToken(c.Request().Context(), cookie.Value)
		if err != nil {
			logger.Warn("authentication failed: invalid session token", slog.String("token", cookie.Value), slog.String("error", err.Error()))
			m.cookieHandler.Delete(c)
			return echo.ErrUnauthorized
		}

		handler.SetUserID(c, session.UserID)
		return next(c)
	}
}
