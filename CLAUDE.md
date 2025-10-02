# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Building and Running
- `make build` - Compiles the server binary to `bin/server`
- `make run` - Builds and runs the server (requires build first)
- `go run cmd/server/main.go` - Run server directly without building

### Testing
- `make test` - Runs all tests with formatted output using gotestfmt
- `make tests` - Alias for test command
- `go test ./internal/service/...` - Run tests for specific package

### Code Generation
- `make mocks` - Generates mock implementations using mockery
- Mock configuration is in `.mockery.yml`
- Mocks are generated in `internal/mocks/` directory

### Setup
- `make setup` - Installs required development tools (gotestfmt, mockery, air, swag)
- `make generate-key` - Generates ECDSA private/public key pair for JWT authentication

## Architecture Overview

This is a Go web API built with Echo framework following clean architecture principles:

### Core Structure
- **Domain Layer** (`internal/domain/`) - Business entities and errors (User, Session, Verification)
- **Repository Layer** (`internal/repository/`) - Data access interfaces and implementations
- **Service Layer** (`internal/service/`) - Business logic (AuthService, UserService, SessionService)
- **Handler Layer** (`internal/handler/`) - HTTP request handlers and routing
- **Infrastructure** (`infra/`) - External integrations (database, email client)

### Key Components
- **Dependency Injection**: Uses uber/dig container for dependency management
- **Authentication**: JWT-based with ECDSA signing, session management
- **Database**: SQLite with GORM ORM
- **Email**: Resend client for notifications
- **Middleware**: CORS, rate limiting, authentication
- **Validation**: Custom validator with localization support

### Important Patterns
- Interfaces defined in service/repository layers for testing
- Error handling with custom domain errors
- Context-aware operations throughout
- Mock generation for all service/repository interfaces

### Configuration
- Environment-based configuration in `config/` package
- Development routes available at `/dev/health` and `/dev/env`
- Rate limiting and CORS configured per environment

### Authentication Flow
- Registration requires email verification
- Login creates JWT tokens and sessions
- Password reset and email change workflows implemented
- Session-based logout and cleanup