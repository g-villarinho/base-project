package main

import (
	"fmt"
	gohttp "net/http"

	"github.com/g-villarinho/base-project/config"
	"github.com/g-villarinho/base-project/infra/client"
	"github.com/g-villarinho/base-project/infra/database"
	"github.com/g-villarinho/base-project/infra/notification"
	"github.com/g-villarinho/base-project/internal/http"
	"github.com/g-villarinho/base-project/internal/http/middleware"
	"github.com/g-villarinho/base-project/internal/repository"
	"github.com/g-villarinho/base-project/internal/service"
	"github.com/g-villarinho/base-project/logger"
	"github.com/g-villarinho/base-project/pkg/injector"
	"github.com/g-villarinho/base-project/pkg/serializer"
	"github.com/g-villarinho/base-project/pkg/validation"
	"github.com/labstack/echo/v4"
	echoMiddleware "github.com/labstack/echo/v4/middleware"
	"go.uber.org/dig"
)

func main() {
	container := provideDependecies()

	config := injector.Resolve[*config.Config](container)
	server := injector.Resolve[*echo.Echo](container)

	server.Logger.Fatal(server.Start(fmt.Sprintf(":%d", config.Server.Port)))
}

func provideDependecies() *dig.Container {
	container := dig.New()

	// General
	injector.Provide(container, config.NewConfig)
	injector.Provide(container, database.NewSqliteDbConnection)
	injector.Provide(container, logger.NewLogger)

	// Client
	injector.Provide(container, client.NewResendClient)

	// Notification
	injector.Provide(container, notification.NewEmailNotification)

	// Service
	injector.Provide(container, service.NewAuthService)
	injector.Provide(container, service.NewSessionService)
	injector.Provide(container, service.NewUserService)

	// Repository
	injector.Provide(container, repository.NewUserRepository)
	injector.Provide(container, repository.NewSessionRepository)
	injector.Provide(container, repository.NewVerificationRepository)

	//Handler
	injector.Provide(container, http.NewCookieHandler)
	injector.Provide(container, http.NewAuthHandler)
	injector.Provide(container, http.NewUserHandler)
	injector.Provide(container, http.NewSessionHandler)

	//Middleware
	injector.Provide(container, middleware.NewAuthMiddleware)

	//Server
	injector.Provide(container, NewServer)

	return container
}

func NewServer(
	config *config.Config,
	authHandler *http.AuthHandler,
	userHandler *http.UserHandler,
	sessionHandler *http.SessionHandler,
	authMiddleware *middleware.AuthMiddleware,
) *echo.Echo {
	e := echo.New()

	e.Validator = validation.NewValidator()
	e.JSONSerializer = serializer.NewSerializer()
	e.HTTPErrorHandler = http.HttpErrorHandler

	e.Use(echoMiddleware.Recover())
	e.Use(echoMiddleware.BodyLimit("10M"))
	e.Use(middleware.Cors(config))
	e.Use(middleware.RateLimiter(config))

	if config.IsDevelopment() {
		registerDevRoutes(e, config)
	}

	registerAuthRoutes(e, authHandler, authMiddleware)
	registerUserRoutes(e, userHandler, authMiddleware)
	registerSessionRoutes(e, sessionHandler, authMiddleware)

	return e
}

func registerDevRoutes(e *echo.Echo, config *config.Config) {
	dev := e.Group("/dev")

	dev.GET("/health", func(c echo.Context) error {
		return c.JSON(gohttp.StatusOK, map[string]string{"status": "ok"})
	})

	dev.GET("/env", func(c echo.Context) error {
		return c.JSON(gohttp.StatusOK, config)
	})
}

func registerAuthRoutes(e *echo.Echo, h *http.AuthHandler, m *middleware.AuthMiddleware) {
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

func registerUserRoutes(e *echo.Echo, h *http.UserHandler, m *middleware.AuthMiddleware) {
	user := e.Group("/user", m.EnsuredAuthenticated)

	user.PATCH("/profile", h.UpdateProfile)
	user.GET("/profile", h.GetProfile)
}

func registerSessionRoutes(e *echo.Echo, h *http.SessionHandler, m *middleware.AuthMiddleware) {
	session := e.Group("/sessions", m.EnsuredAuthenticated)

	session.DELETE("/:session_id", h.RevokeSession)
	session.DELETE("", h.RevokeAllSessions)
}
