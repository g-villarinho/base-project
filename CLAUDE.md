# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Development Commands

```bash
# Install development dependencies (gotestfmt, mockery, air, swag)
make setup

# Build the application (outputs to bin/api)
make build

# Build and run the server
make run

# Run all tests with formatted output
make test

# Regenerate mocks from interfaces
make mocks
```

## Architecture Overview

This is a Go REST API following **Clean Architecture** with Domain-Driven Design principles. The codebase is organized into 5 distinct layers:

### Layer Structure and Responsibilities

1. **API Layer** (`internal/api/`)
   - HTTP handlers in `handler/` - Process HTTP requests/responses
   - Middleware in `middleware/` - Authentication, CORS, rate limiting
   - Request/response DTOs in `model/` - API contracts
   - Routes in `routes.go` - HTTP route definitions

2. **Service Layer** (`internal/service/`)
   - Business logic and orchestration
   - Interface definitions (public) + private implementations
   - Coordinate between repositories, external services
   - Map repository errors to domain errors

3. **Domain Layer** (`internal/domain/`)
   - Core business entities (User, Session, Verification)
   - Domain-specific error types
   - Business rules and validation

4. **Repository Layer** (`internal/repository/`)
   - Data access abstraction
   - Interface definitions (public) + private implementations
   - GORM database operations
   - Repository-specific errors

5. **Infrastructure Layer** (`internal/infra/`)
   - `sqlite/` - Database connection and configuration
   - `client/` - External API clients (Resend email)
   - `notification/` - Email notification service

### Data Flow Pattern

```
HTTP Request → Handler → Service → Repository → Database
                  ↓         ↓
              Middleware  Domain
```

## Dependency Injection Pattern

All dependencies are managed through **Uber/dig** container, initialized in `internal/api/dependecies.go:ProvideDependencies()`.

### Adding a New Dependency

1. Define the interface in the appropriate package (service/repository)
2. Implement the interface as a private struct
3. Create a constructor function (e.g., `NewUserService`)
4. Register in `ProvideDependencies()` using `injector.Provide(container, NewUserService)`
5. Inject via constructor parameters (dig handles resolution)

Example from `internal/service/user.go`:
```go
// 1. Public interface
type UserService interface {
    GetUser(ctx context.Context, userID uuid.UUID) (*domain.User, error)
}

// 2. Private implementation
type userService struct {
    userRepo repository.UserRepository
    logger   *slog.Logger
}

// 3. Constructor with injected dependencies
func NewUserService(userRepo repository.UserRepository, logger *slog.Logger) UserService {
    return &userService{
        userRepo: userRepo,
        logger:   logger.With(slog.String("service", "user")),
    }
}
```

## Configuration Management

Configuration uses **Viper** to load from YAML files and environment variables.

### Configuration Priority
1. Environment variables (uppercase with underscores: `SERVER_PORT`, `RESEND_API_KEY`)
2. `config.yaml` file in project root
3. Alternative config files: `config.qa.yaml`

### Adding New Configuration

1. Add field to `config/model.go` struct
2. Add default value to `config.yaml.example`
3. Access via injected `*config.Config` in constructors

Example environment variable override:
```bash
SERVER_PORT=8080 RESEND_API_KEY=re_abc123 ./bin/api
```

## Testing Conventions

Tests use **Testify** for assertions and **Mockery** for generating mocks.

### Mock Generation

Mocks are auto-generated from interfaces using `.mockery.yml` configuration:
- Generated to `internal/mocks/` directory
- Covers all service and repository interfaces
- Naming: `{InterfaceName}Mock` (e.g., `UserServiceMock`)

After adding/modifying an interface:
```bash
make mocks  # Regenerates all mocks
```

### Test Structure Example

```go
func TestUserService_GetUser(t *testing.T) {
    // Arrange
    mockRepo := new(mocks.UserRepositoryMock)
    service := service.NewUserService(mockRepo, logger)

    mockRepo.On("FindByID", mock.Anything, userID).
        Return(&domain.User{...}, nil)

    // Act
    user, err := service.GetUser(context.Background(), userID)

    // Assert
    assert.NoError(t, err)
    assert.NotNil(t, user)
    mockRepo.AssertExpectations(t)
}
```

## Key Design Patterns

### Interface-Based Design
- All services and repositories define public interfaces
- Private struct implementations
- Enables testability through dependency injection

### Constructor Pattern
- Constructor functions named `NewX` (e.g., `NewUserService`)
- Accept dependencies as parameters
- Return interface type, not concrete struct

### Error Mapping Between Layers
Services translate repository errors to domain errors:
```go
user, err := s.userRepo.FindByID(ctx, userID)
if err != nil {
    if err == repository.ErrUserNotFound {
        return nil, domain.ErrUserNotFound  // Map to domain error
    }
    return nil, fmt.Errorf("find user by id: %w", err)
}
```

### Named Dependencies
For multiple instances of same type, use `dig.Name`:
```go
injector.Provide(container, NewSessionSigner, dig.Name("sessionSigner"))
```

## Database and Migrations

### SQLite with GORM
- Database file: `users.db` (configurable in config.yaml)
- Auto-migration: GORM automatically creates/updates tables from domain structs
- Connection pooling configured via config:
  - `maxconn`: Maximum open connections
  - `maxidle`: Maximum idle connections
  - `maxlifetime`: Connection lifetime

### Adding a New Entity
1. Define struct in `internal/domain/`
2. Add GORM tags for table mapping
3. Create repository interface and implementation
4. Auto-migration runs on application start

## Security and Authentication

### Password Hashing
- **Argon2** via `pkg/hash/argon2.go`
- Memory: 64MB, Iterations: 3, Parallelism: 2, Salt: 16 bytes, Key: 32 bytes

### JWT Authentication
- Token generation in `pkg/crypto/`
- Session-based authentication with secure cookies
- Middleware: `internal/api/middleware/auth.go`

### Session Management
- Session tokens generated via `crypto.Signer`
- Stored in cookies with configurable security settings
- Session duration: 7 days (default, configurable)

## Package Layer (`pkg/`)

Reusable utilities independent of business logic:
- `crypto/` - JWT signing, token generation
- `hash/` - Argon2 password hashing
- `serializer/` - JSON serialization (json-iterator)
- `validation/` - Input validation with error translation
- `injector/` - Wrapper for Uber/dig operations
