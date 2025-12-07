package api

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/g-villarinho/base-project/config"
	"github.com/g-villarinho/base-project/internal/api/handler"
	"github.com/g-villarinho/base-project/internal/api/middleware"
	"github.com/g-villarinho/base-project/pkg/serializer"
	"github.com/g-villarinho/base-project/pkg/validation"
	"github.com/labstack/echo/v4"
	echoMiddleware "github.com/labstack/echo/v4/middleware"
	"go.uber.org/dig"
)

type API struct {
	echo            *echo.Echo
	port            int
	shutdownTimeout time.Duration
}

type NewAPIParams struct {
	dig.In

	config         *config.Config
	authHandler    *handler.AuthHandler
	userHandler    *handler.UserHandler
	sessionHandler *handler.SessionHandler
	authMiddleware *middleware.AuthMiddleware
}

func NewAPI(params NewAPIParams) *API {
	e := echo.New()

	e.Validator = validation.NewValidator()
	e.JSONSerializer = serializer.NewSerializer()
	e.IPExtractor = echo.ExtractIPFromXFFHeader()

	e.Use(echoMiddleware.Recover())
	e.Use(echoMiddleware.BodyLimit("10M"))
	e.Use(middleware.Cors(params.config))
	e.Use(middleware.RateLimiter(params.config))
	e.Use(middleware.ClientInfo())

	if params.config.IsDevelopment() {
		registerDevRoutes(e, params.config)
	}

	registerAuthRoutes(e, params.authHandler, params.authMiddleware)
	registerUserRoutes(e, params.userHandler, params.authMiddleware)
	registerSessionRoutes(e, params.sessionHandler, params.authMiddleware)

	return &API{
		echo:            e,
		port:            params.config.Server.Port,
		shutdownTimeout: 10 * time.Second,
	}
}

func (s *API) Start() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	go func() {
		address := fmt.Sprintf(":%d", s.port)
		if err := s.echo.Start(address); err != nil {
			s.echo.Logger.Info("Shutting down the server")
		}
	}()

	<-quit
	s.echo.Logger.Info("Server is shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()

	if err := s.echo.Shutdown(ctx); err != nil {
		s.echo.Logger.Error("server forced to shutdown", err)
	}

	s.echo.Logger.Info("Server exited gracefully")
}
