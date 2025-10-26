# Logging Guidelines

This document defines logging best practices for this codebase based on established patterns in the authentication flow.

## Core Philosophy

**Layer Responsibilities:**
- **Handler Layer**: Primary logging responsibility. Log before returning HTTP error responses.
- **Service Layer**: Minimal logging. Return errors for handlers to log. Only log:
  - Non-critical failures that don't stop execution
  - Important business events that need tracking
  - When you have context the handler won't have

**Rationale**: Handlers have HTTP context (status codes, client info) and are the final decision point for errors. Services should be focused on business logic, not HTTP concerns.

---

## Log Levels

### `Error` - Internal Server Errors (5xx)
Use when unexpected failures occur that are **not the client's fault**.

**Examples:**
- Database connection failures
- External service errors
- Unexpected nil pointers
- Failed to hash password

```go
logger.Error(
    "Failed to register account due to internal error",
    slog.Any("error", err),
)
```

### `Warn` - Client Errors (4xx) & Business Rule Violations
Use when the request **fails due to client input or business rules**.

**Examples:**
- Email already exists (409 Conflict)
- User not found (404 Not Found)
- Password mismatch (401 Unauthorized)
- Failed to bind payload (400 Bad Request)

```go
logger.Warn("Registration conflict: email already exists")
logger.Warn("password mismatch")
logger.Warn("Failed to bind payload", slog.Any("error", err))
```

### `Info` - Informational Events
Use for **expected events** that are useful for understanding application flow.

**Examples:**
- Validation failures
- Successful operations (use sparingly)

```go
logger.Info("Payload validation failed")
```

---

## Context Enrichment

### Handler Layer Context
Always create a scoped logger with `method` and `path`:

```go
logger := h.logger.With(
    slog.String("method", "RegisterAccount"),
    slog.String("path", c.Path()),
)
```

**Additional Context** (when available):
- `error`: Include error details for debugging
- Request-specific data (avoid logging sensitive info like passwords)

### Service Layer Context
Create scoped logger with `method` and relevant business identifiers:

```go
logger := s.logger.With(
    slog.String("method", "UpdatePassword"),
    slog.String("user_id", userID.String()),
)
```

**When to add user_id:**
- User-specific operations (UpdatePassword, RequestChangeEmail, etc.)
- NOT on registration (user doesn't exist yet)
- NOT on login failures before identification (prevents enumeration)

---

## Practical Examples

### Example 1: Handler Logging (RegisterAccount)
**File**: `internal/server/handler/auth.go:33-66`

```go
func (h *AuthHandler) RegisterAccount(c echo.Context) error {
    logger := h.logger.With(
        slog.String("method", "RegisterAccount"),
        slog.String("path", c.Path()),
    )

    var payload model.RegisterAccountPayload
    if err := c.Bind(&payload); err != nil {
        logger.Warn("Failed to bind payload", slog.Any("error", err))
        return BadRequest(c, err)
    }

    if err := c.Validate(payload); err != nil {
        logger.Info("Payload validation failed")
        return HandleValidationError(c, payload, err)
    }

    err := h.authService.RegisterAccount(c.Request().Context(), payload.Name, payload.Email, payload.Password)
    if err != nil {
        if errors.Is(err, domain.ErrEmailAlreadyExists) {
            logger.Warn("Registration conflict: email already exists")
            return ConflictError(c, "The email address provided is not available")
        }

        logger.Error(
            "Failed to register account due to internal error",
            slog.Any("error", err),
        )
        return InternalServerError(c, "Failed to register account")
    }

    return c.NoContent(http.StatusCreated)
}
```

**Pattern**: Scoped logger → Log at each error path → Match log level to HTTP status

### Example 2: Service Non-Critical Error Logging (Login)
**File**: `internal/service/auth.go:130-141`

```go
if !user.IsEmailVerified() {
    if err := s.verificationService.SendVerificationEmail(ctx, user, domain.VerificationEmailFlow); err != nil {
        s.logger.Error(
            "Failed to send verification email during login",
            slog.String("user_id", user.ID.String()),
            slog.Any("error", err),
        )
    }

    return result, domain.ErrEmailNotVerified
}
```

**Pattern**: Log non-critical failures but continue execution. Handler will log the main error (ErrEmailNotVerified).

### Example 3: Service Logging with User Context (UpdatePassword)
**File**: `internal/service/auth.go:154-187`

```go
func (s *authService) UpdatePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error {
    logger := s.logger.With(
        slog.String("method", "UpdatePassword"),
        slog.String("user_id", userID.String()),
    )

    user, err := s.userRepository.FindByID(ctx, userID)
    if err != nil {
        if errors.Is(err, repository.ErrUserNotFound) {
            logger.Warn("no user found with given ID")
            return domain.ErrUserNotFound
        }

        return fmt.Errorf("find user by id %s: %w", userID, err)
    }

    err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword))
    if err != nil {
        logger.Warn("password mismatch")
        return domain.ErrPasswordMismatch
    }

    // ... rest of method
}
```

**Pattern**: Create scoped logger with user_id → Log business rule violations (Warn) → Return domain errors

---

## Rules & Anti-Patterns

### ✅ DO

1. **Create scoped loggers** with relevant context at the start of handler/service methods
2. **Log before returning errors** in handlers
3. **Match log levels to HTTP status codes**: Warn for 4xx, Error for 5xx
4. **Include error details** using `slog.Any("error", err)` for debugging
5. **Log non-critical failures** in services (e.g., failed email sends that shouldn't break the flow)
6. **Use structured logging** with key-value pairs (slog.String, slog.Any)

### ❌ DON'T

1. **Don't duplicate logging**: If service logs an error, handler shouldn't log the same error again
2. **Don't log in both service and handler** for the same error path
3. **Don't log sensitive data**: passwords, tokens, session IDs, credit cards
4. **Don't log user_id on unauthenticated errors** (prevents user enumeration)
5. **Don't use Error level for client mistakes** (use Warn instead)
6. **Don't log without context**: Always use scoped loggers with method/path/user_id

---

## Special Cases

### User Enumeration Prevention
When logging authentication failures, avoid including user identifiers until the user is positively identified.

**Example from Login flow** (`internal/service/auth.go:96-152`):

```go
func (s *authService) Login(ctx context.Context, input model.LoginInput) (*domain.LoginResult, error) {
    // 1. Find user by email
    user, err := s.userRepository.FindByEmail(ctx, input.Email)
    if err != nil {
        if errors.Is(err, repository.ErrUserNotFound) {
            // DON'T log email here - prevents enumeration
            return nil, domain.ErrInvalidCredentials
        }
        return nil, fmt.Errorf("authService.Login: find user by email: %w", err)
    }

    // 2. User identified! Create result with UserID
    result := &domain.LoginResult{
        UserID: user.ID,
    }

    // 3. From now on, we CAN log with user_id because user is identified
    if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)); err != nil {
        // Handler will log this with user_id from result
        return result, domain.ErrInvalidCredentials
    }

    // ... rest of method
}
```

### Silent Failures for Security
Sometimes we return success but don't perform the action to prevent enumeration.

**Example** (`internal/server/handler/auth.go:184-191`):

```go
if err := h.authService.RequestPasswordReset(c.Request().Context(), payload.Email); err != nil {
    if errors.Is(err, domain.ErrUserNotFound) {
        // To prevent user enumeration, we return 200 OK even if the user is not found.
        return c.NoContent(http.StatusOK)
    }

    return InternalServerError(c, "Failed to request password reset")
}
```

**Don't log** user-not-found in this case - it would defeat the security purpose.

---

## Quick Reference

| Situation | Level | Where | Include user_id? |
|-----------|-------|-------|------------------|
| Bad request / binding error | Warn | Handler | No (unauthenticated) |
| Validation failure | Info | Handler | No (unauthenticated) |
| Email already exists | Warn | Handler | No (user doesn't exist) |
| User not found (authenticated endpoint) | Warn | Service | Yes |
| Password mismatch | Warn | Service | Yes |
| Database error | Error | Handler | If available |
| External service failure | Error | Handler/Service | If available |
| Non-critical email send failure | Error | Service | Yes |
| Login failure (user not found) | None | N/A | No (security) |
| Login failure (wrong password, after identification) | Warn | Handler | Yes (from result) |

---

## Summary

1. **Handlers log, services return errors** (except for non-critical failures)
2. **Warn for 4xx, Error for 5xx**
3. **Always use scoped loggers** with method/path/user_id context
4. **Include error details** for debugging
5. **Be mindful of security**: Don't log user identifiers on enumeration-sensitive endpoints
6. **Don't duplicate logging** between layers

Follow these patterns to maintain consistent, secure, and debuggable logging throughout the codebase.
