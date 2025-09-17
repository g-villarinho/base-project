package middleware

import (
	"log/slog"

	"github.com/g-villarinho/user-demo/internal/handler"
	"github.com/g-villarinho/user-demo/internal/service"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type AuthMiddleware struct {
	jwtService service.JwtService
	logger     *slog.Logger
}

func NewAuthMiddleware(jwtService service.JwtService, logger *slog.Logger) *AuthMiddleware {
	return &AuthMiddleware{
		jwtService: jwtService,
		logger:     logger.With(slog.String("middleware", "auth")),
	}
}

func (m *AuthMiddleware) EnsuredAuthenticated(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		logger := m.logger.With(
			slog.String("path", c.Request().URL.Path),
			slog.String("method", c.Request().Method),
		)

		cookie, err := handler.GetCookie(c)
		if err != nil {
			logger.Warn("authentication failed: no cookie found")
			return echo.ErrUnauthorized
		}

		if cookie.Value == "" {
			logger.Warn("authentication failed: empty cookie value")
			handler.DeleteCookie(c)
			return echo.ErrUnauthorized
		}

		claims, err := m.jwtService.VerifyAccessToken(c.Request().Context(), cookie.Value)
		if err != nil {
			logger.Warn("authentication failed: invalid token", "error", err)
			handler.DeleteCookie(c)
			return echo.ErrUnauthorized
		}

		userID, err := uuid.Parse(claims.Subject)
		if err != nil {
			logger.Error("authentication failed: invalid user ID in token", "subject", claims.Subject, "error", err)
			handler.DeleteCookie(c)
			return echo.ErrUnauthorized
		}

		handler.SetUserID(c, userID)
		return next(c)
	}
}
