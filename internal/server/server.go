package server

import (
	"github.com/g-villarinho/base-project/config"
	"github.com/g-villarinho/base-project/internal/server/handler"
	"github.com/g-villarinho/base-project/internal/server/middleware"
	"github.com/g-villarinho/base-project/pkg/serializer"
	"github.com/g-villarinho/base-project/pkg/validation"
	"github.com/labstack/echo/v4"
	echoMiddleware "github.com/labstack/echo/v4/middleware"
)

func NewServer(
	config *config.Config,
	authHandler *handler.AuthHandler,
	userHandler *handler.UserHandler,
	sessionHandler *handler.SessionHandler,
	authMiddleware *middleware.AuthMiddleware,
) *echo.Echo {
	e := echo.New()

	e.Validator = validation.NewValidator()
	e.JSONSerializer = serializer.NewSerializer()
	e.IPExtractor = echo.ExtractIPFromXFFHeader()

	e.Use(echoMiddleware.Recover())
	e.Use(echoMiddleware.BodyLimit("10M"))
	e.Use(middleware.Cors(config))
	e.Use(middleware.RateLimiter(config))
	e.Use(middleware.ClientInfo())

	if config.IsDevelopment() {
		registerDevRoutes(e, config)
	}

	registerAuthRoutes(e, authHandler, authMiddleware)
	registerUserRoutes(e, userHandler, authMiddleware)
	registerSessionRoutes(e, sessionHandler, authMiddleware)

	return e
}
