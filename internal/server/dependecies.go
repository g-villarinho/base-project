package server

import (
	"github.com/g-villarinho/base-project/config"
	"github.com/g-villarinho/base-project/internal/infra/client"
	"github.com/g-villarinho/base-project/internal/infra/notification"
	"github.com/g-villarinho/base-project/internal/infra/sqlite"
	"github.com/g-villarinho/base-project/internal/repository"
	"github.com/g-villarinho/base-project/internal/server/handler"
	"github.com/g-villarinho/base-project/internal/server/middleware"
	"github.com/g-villarinho/base-project/internal/service"
	"github.com/g-villarinho/base-project/logger"
	"github.com/g-villarinho/base-project/pkg/crypto"
	"github.com/g-villarinho/base-project/pkg/injector"
	"go.uber.org/dig"
)

func ProvideDependencies() *dig.Container {
	container := dig.New()

	// General
	injector.Provide(container, config.NewConfig)
	injector.Provide(container, sqlite.NewDbConnection)
	injector.Provide(container, logger.NewLogger)
	injector.Provide(container, NewSessionSigner, dig.Name("sessionSigner"))

	// Client
	injector.Provide(container, client.NewResendClient)

	// Notification
	injector.Provide(container, notification.NewEmailNotification)

	// Service
	injector.Provide(container, service.NewVerificationService)
	injector.Provide(container, service.NewAuthService)
	injector.Provide(container, service.NewSessionService)
	injector.Provide(container, service.NewUserService)

	// Repository
	injector.Provide(container, repository.NewUserRepository)
	injector.Provide(container, repository.NewSessionRepository)
	injector.Provide(container, repository.NewVerificationRepository)

	//Handler
	injector.Provide(container, handler.NewCookieHandler)
	injector.Provide(container, handler.NewAuthHandler)
	injector.Provide(container, handler.NewUserHandler)
	injector.Provide(container, handler.NewSessionHandler)

	//Middleware
	injector.Provide(container, middleware.NewAuthMiddleware)

	//Server
	injector.Provide(container, NewServer)

	return container
}

func NewSessionSigner(cfg *config.Config) crypto.Signer {
	return crypto.NewSigner(cfg.Session.Secret)
}
