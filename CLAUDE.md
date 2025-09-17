# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go-based user authentication service built with Echo framework. It provides a RESTful API for user registration, authentication, email verification, and password management using JWT tokens and SQLite database.

## Key Commands

### Development Setup
```bash
make setup          # Install all necessary project dependencies (gotestfmt, mockery, air, swag, newman)
make generate-key    # Generate ECDSA authentication keys (ecdsa_private.pem, ecdsa_public.pem)
```

### Building and Running
```bash
make build          # Build the server binary to bin/server
make run            # Build and run the server (runs on port from config)
```

### Testing
```bash
make test           # Run all tests with formatted output using gotestfmt
make tests          # Alias for make test
```

### Development Tools
```bash
make mocks          # Generate mocks for all interfaces using mockery
```

## Architecture

### Directory Structure
- `cmd/server/` - Application entrypoint with dependency injection setup
- `internal/` - Private application code
  - `handler/` - HTTP handlers and middleware
  - `service/` - Business logic layer
  - `repository/` - Database access layer
  - `model/` - Database models
  - `dto/` - Data transfer objects
  - `mocks/` - Generated mocks for testing
- `pkg/` - Public packages that could be imported by other projects
  - `injector/` - Dependency injection utilities
  - `keyparser/` - ECDSA key parsing utilities
  - `serializer/` - JSON serialization
  - `validation/` - Request validation
- `config/` - Configuration management
- `infra/` - Infrastructure setup (database connections)

### Dependency Injection
The application uses `go.uber.org/dig` for dependency injection. All dependencies are registered in `cmd/server/main.go` in the `provideDependencies()` function.

### Database
- Uses SQLite with GORM ORM
- Database file: `users.db`
- Automatic migrations handled by GORM

### Authentication
- JWT-based authentication using ECDSA signing
- Private/public key pair stored as PEM files
- Middleware for protecting authenticated routes

## Testing Standards

Test files follow specific conventions defined in `.claude/rules/TESTS.md`:
- Test files should be named `*_test.go` and located in the same package
- Each method gets one main test function: `TestServiceName_MethodName`
- Use `t.Run()` for subtests with descriptive names: "should [action] when [condition]"
- All external dependencies must be mocked using mocks from `internal/mocks/`
- Generate missing mocks with `make mocks`

## Configuration

The application loads configuration from:
1. Environment variables
2. `.env` file (for development)
3. `.env.test` file (for testing)

Key configuration areas include server port, database settings, JWT signing keys, and feature flags.