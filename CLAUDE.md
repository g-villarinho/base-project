# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Building and Running
- `make build` - Compiles the server binary to `bin/server`
- `make run` - Builds and runs the server
- `go run cmd/server/main.go` - Run server directly without building

### Testing
- `make test` - Runs all tests with formatted output using gotestfmt
- `go test ./internal/service/...` - Run tests for specific package
- `go test -v ./internal/service -run TestName` - Run a single test

### E2E Testing
- `make run-e2e` - Runs complete E2E test suite (spins up docker-compose, seeds data, runs tests, tears down)
- `make test-e2e-up` - Starts E2E test environment with docker-compose
- `make test-e2e-down` - Tears down E2E test environment
- `make test-e2e-logs` - Shows logs from E2E test environment
- `go test -v ./tests/e2e/...` - Run E2E tests manually (requires environment to be up)

### Code Generation
- `make mocks` - Generates mock implementations using mockery
- Mock configuration is in `.mockery.yml`
- Mocks are generated in `internal/mocks/` directory
- Mocks are auto-generated for all interfaces in: `service/`, `repository/`, `pkg/keyparser/`, `infra/notification/`

### Setup
- `make setup` - Installs required development tools (gotestfmt, mockery, air, swag)

## Architecture Overview

This is a Go web API built with Echo framework following clean architecture principles.

### Core Structure
- **Domain Layer** (`internal/domain/`) - Business entities and domain errors (User, Session, Verification)
- **Service Layer** (`internal/service/`) - Business logic (AuthService, UserService, SessionService, VerificationService)
- **Repository Layer** (`internal/repository/`) - Data access interfaces and implementations
- **Handler Layer** (`internal/server/handler/`) - HTTP request handlers
- **Infrastructure** (`internal/infra/`) - External integrations (database, email client, notifications)

### Server Package Structure (`internal/server/`)
- `server.go` - Echo server initialization with middleware and error handling
- `routes.go` - Route registration functions (registerAuthRoutes, registerUserRoutes, etc.)
- `error.go` - Custom HTTP error handler with validation error formatting
- `dependencies.go` - Dependency injection container setup using uber/dig
- `echoctx/` - Echo context utilities for storing/retrieving user/session IDs
- `handler/` - HTTP handlers (AuthHandler, UserHandler, SessionHandler, CookieHandler)
- `middleware/` - Custom middleware (AuthMiddleware, CORS, RateLimiter)

**Important**: The `echoctx` package provides context helpers (`SetUserID`, `GetUserID`, `SetSessionID`, `GetSessionID`) that are used across handlers and middleware to avoid import cycles.

### Dependency Injection
- Uses uber/dig for dependency management
- All dependencies configured in `internal/server/dependencies.go` via `ProvideDependencies()`
- Dependencies are resolved in `cmd/server/main.go` using `pkg/injector` helpers
- Registration order: Config → Database → Logger → Clients → Notifications → Services → Repositories → Handlers → Middleware → Server

### Key Components
- **Authentication**: JWT-based with ECDSA signing, session management
- **Database**: SQLite with GORM ORM (`internal/infra/database/`)
- **Email**: Resend client for notifications (`internal/infra/client/`, `internal/infra/notification/`)
- **Middleware**: CORS, rate limiting, authentication (`internal/server/middleware/`)
- **Validation**: Custom validator with localization support using go-playground/validator (`pkg/validation/`)
- **Serialization**: jsoniter for high-performance JSON serialization (`pkg/serializer/`)

### Important Patterns
- All service and repository interfaces are defined in their respective packages
- Mock generation configured for all interfaces via `.mockery.yml`
- Error handling uses custom domain errors (e.g., `domain.ErrUserNotFound`, `domain.ErrInvalidCredentials`)
- All operations are context-aware for cancellation and timeouts
- Handlers return Echo errors; custom error handler formats validation errors

### Configuration
- Configuration managed by Viper (`github.com/spf13/viper`) in `config/` package
- Supports multiple formats: YAML, JSON, TOML, and environment variables
- Config precedence: Environment variables > Config file > Defaults
- Primary config file: `config.yaml` (optional - see `config.yaml.example` for reference)
- Environment variables use uppercase with underscores (e.g., `SERVER_PORT`, `RESEND_API_KEY`)
- Hierarchical naming: config fields use dot notation (`server.port` maps to `SERVER_PORT` env var)
- Configuration loaded once at application startup
- Struct fields use `mapstructure` tags for Viper unmarshal
- Development routes available at `/dev/health` and `/dev/env` (only in dev mode)
- Rate limiting and CORS configured per environment

### Authentication Flow
- Registration requires email verification via token sent to email
- Login creates JWT tokens and database-backed sessions
- Password reset and email change workflows use verification tokens
- Session-based logout with cookie deletion
- Middleware (`AuthMiddleware.EnsuredAuthenticated`) validates session and sets user/session ID in context

### Testing
- Service tests use mockery-generated mocks
- Handler tests use mock services and cookie handlers
- E2E tests run in Docker with docker-compose setup in `tests/`
- Test data seeding via `tests/seed.go`
