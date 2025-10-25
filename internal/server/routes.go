package server

import (
	"net/http"

	"github.com/g-villarinho/base-project/config"
	"github.com/g-villarinho/base-project/internal/server/handler"
	"github.com/g-villarinho/base-project/internal/server/middleware"
	"github.com/labstack/echo/v4"
)

func registerDevRoutes(e *echo.Echo, config *config.Config) {
	dev := e.Group("/dev")

	dev.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	dev.GET("/env", func(c echo.Context) error {
		return c.JSON(http.StatusOK, config)
	})
}

func registerAuthRoutes(e *echo.Echo, h *handler.AuthHandler, m *middleware.AuthMiddleware) {
	auth := e.Group("/auth")

	auth.POST("/register", h.RegisterAccount)
	auth.GET("/verify-email", h.VerifyEmail)
	auth.POST("/login", h.Login)
	auth.PATCH("/password", h.UpdatePassword, m.EnsuredAuthenticated)
	auth.DELETE("/logout", h.Logout, m.EnsuredAuthenticated)
	auth.POST("/reset-password", h.RequestResetPassword)
	auth.POST("/reset-password/confirm", h.ConfirmResetPassword)
	auth.POST("/change-email", h.RequestChangeEmail, m.EnsuredAuthenticated)
	auth.GET("/change-email/confirm", h.ConfirmChangeEmail, m.EnsuredAuthenticated)
}

func registerUserRoutes(e *echo.Echo, h *handler.UserHandler, m *middleware.AuthMiddleware) {
	user := e.Group("/user", m.EnsuredAuthenticated)

	user.PATCH("/profile", h.UpdateProfile)
	user.GET("/profile", h.GetProfile)
}

func registerSessionRoutes(e *echo.Echo, h *handler.SessionHandler, m *middleware.AuthMiddleware) {
	session := e.Group("/sessions", m.EnsuredAuthenticated)

	session.DELETE("/:session_id", h.RevokeSession)
	session.DELETE("", h.RevokeAllSessions)
}
