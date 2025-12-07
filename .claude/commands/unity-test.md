# TASK

Write unit tests for the provided file.

**Required parameter:** file (the file to write tests for)
**Optional parameter:** method name (specific method to test)

Usage:
- `/unity-test <file>` - Write tests for all methods in the file
- `/unity-test <file> <method_name>` - Write tests only for the specified method

If a specific method is provided, focus only on that method. Otherwise, write tests for all public methods in the file.

---

## Structure and Naming

### File Naming
- For a service `auth.go` → test file: `auth_test.go`
- For a repository `user_repository.go` → test file: `user_repository_test.go`
- For a handler `auth_handler.go` → test file: `auth_handler_test.go`

### Test Method Structure
- **One test method for each service/repository method**
- Method name: `Test[MethodName]`
- Example: `TestLogin`, `TestAuthenticate`, `TestSendVerificationCode`

### Using `t.Run()` for Subtests
- Inside each test method, use `t.Run()` with descriptive descriptions
- Format: `t.Run("should [description of expected behavior]", func(t *testing.T) { ... })`
- Examples:
  - `t.Run("should return success when valid credentials are provided", func(t *testing.T) { ... })`
  - `t.Run("should return error when email is invalid", func(t *testing.T) { ... })`
  - `t.Run("should return error when OTP code is expired", func(t *testing.T) { ... })`

## Test Structure Pattern

```go
func TestLogin(t *testing.T) {
    t.Run("should return success when valid credentials are provided", func(t *testing.T) {
        // Arrange
        // Setup mocks, test data, etc.
        
        // Act
        // Call the method being tested
        
        // Assert
        // Verify results
    })
    
    t.Run("should return error when email is invalid", func(t *testing.T) {
        // Arrange
        // Act
        // Assert
    })
    
    t.Run("should return error when password is incorrect", func(t *testing.T) {
        // Arrange
        // Act
        // Assert
    })
}
```

## Setup Helpers with `t.Helper()`

### Purpose
Setup helpers are utility functions that initialize test dependencies (mocks, services, configs) to reduce code duplication and improve test readability.

### Rules for Setup Helpers

1. **Always use `t.Helper()` as the first line**
   - Marks the function as a test helper
   - When tests fail, stack traces point to the test call site, not the helper itself
   - Makes debugging easier

2. **Naming Convention**
   - Format: `setup[ComponentName](t *testing.T)`
   - Examples: `setupUserService`, `setupSessionService`, `setupAuthHandler`

3. **Return Pattern**
   - Return the component being tested first
   - Return mock dependencies after
   - Example: `return service, mockRepo, mockOtherDep`

4. **What to Include**
   - Initialize all mocks needed for the component
   - Create minimal configuration (use test-friendly values)
   - Initialize loggers with `io.Discard` to avoid log noise
   - Return everything needed for tests

### Example: Service Setup Helper

```go
func setupUserService(t *testing.T) (UserService, *mocks.UserRepositoryMock) {
    t.Helper()

    // Initialize mocks
    userRepoMock := mocks.NewUserRepositoryMock(t)

    // Create test logger (discard output)
    logger := slog.New(slog.NewTextHandler(io.Discard, nil))

    // Initialize service with dependencies
    service := NewUserService(userRepoMock, logger)

    return service, userRepoMock
}
```

### Example: Service with Configuration

```go
func setupSessionService(t *testing.T) (SessionService, *mocks.SessionRepositoryMock) {
    t.Helper()

    sessionRepoMock := mocks.NewSessionRepositoryMock(t)
    logger := slog.New(slog.NewTextHandler(io.Discard, nil))

    // Create minimal test config
    cfg := &config.Config{
        Session: config.Session{
            Duration: 24 * time.Hour,
        },
    }

    service := NewSessionService(sessionRepoMock, cfg, logger)
    return service, sessionRepoMock
}
```

### Usage in Tests

```go
func TestUserService_GetUser(t *testing.T) {
    t.Run("should return user when user exists", func(t *testing.T) {
        // Use setup helper - clean and simple
        service, userRepoMock := setupUserService(t)

        ctx := context.Background()
        userID := uuid.New()
        expectedUser := &domain.User{
            ID:    userID,
            Name:  "John Doe",
            Email: "john@example.com",
        }

        userRepoMock.On("FindByID", ctx, userID).Return(expectedUser, nil)

        user, err := service.GetUser(ctx, userID)

        assert.NoError(t, err)
        assert.Equal(t, expectedUser, user)
        userRepoMock.AssertExpectations(t)
    })
}
```

### Benefits

1. **DRY Principle**: Avoid repeating mock initialization in every test
2. **Consistency**: All tests use the same setup pattern
3. **Easy Updates**: Change setup in one place, affects all tests
4. **Better Error Messages**: `t.Helper()` ensures stack traces point to actual test failures
5. **Readability**: Tests focus on the scenario, not boilerplate

## Additional Best Practices

### 1. Test Organization (AAA Pattern)
- **Arrange**: Prepare data, mocks, and dependencies
- **Act**: Execute the method being tested
- **Assert**: Verify expected results

### 2. Using Mocks
- Use the generated mocks in the `internal/mocks/` folder
- Set clear expectations on mocks
- Verify that all expectations were met

### 3. Descriptive Names
- Use names that describe the scenario and expected result
- Avoid generic names like "test1", "test2"
- Good examples:
  - `"should return user when valid ID is provided"`
  - `"should return error when user not found"`
  - `"should validate email format correctly"`

### 4. Scenario Coverage
- Test success cases
- Test error cases
- Test edge cases (empty values, nulls, etc.)
- Test input validations

### 5. Setup and Teardown
- Use `t.Cleanup()` for automatic cleanup
- Configure mocks at the beginning of each subtest
- Avoid dependencies between tests

### 6. Assertions
- Use `assert` and `require` from testify
- Use `require` for conditions that should stop the test if they fail
- Use `assert` for verifications that can continue the test

### 7. Test Data
- Create realistic test data
- Use factories or helpers to create test data
- Avoid hardcoded data when possible

## Complete Example

```go
func TestAuthenticate(t *testing.T) {
    t.Run("should return authentication success when valid OTP code is provided", func(t *testing.T) {
        // Arrange
        ctx := context.Background()
        code := "123456"
        otpID := "test-otp-id"
        
        mockOTPService := mocks.NewOTPServiceMock(t)
        mockOTPService.EXPECT().
            ValidateOTP(ctx, code, otpID).
            Return(true, nil)
        
        authService := NewAuthService(mockOTPService)
        
        // Act
        result, err := authService.Authenticate(ctx, code, otpID)
        
        // Assert
        require.NoError(t, err)
        assert.NotNil(t, result)
        assert.True(t, result.Success)
    })
    
    t.Run("should return error when OTP code is invalid", func(t *testing.T) {
        // Arrange
        ctx := context.Background()
        code := "invalid"
        otpID := "test-otp-id"
        
        mockOTPService := mocks.NewOTPServiceMock(t)
        mockOTPService.EXPECT().
            ValidateOTP(ctx, code, otpID).
            Return(false, errors.New("invalid OTP"))
        
        authService := NewAuthService(mockOTPService)
        
        // Act
        result, err := authService.Authenticate(ctx, code, otpID)
        
        // Assert
        require.Error(t, err)
        assert.Nil(t, result)
        assert.Contains(t, err.Error(), "invalid OTP")
    })
    
    t.Run("should return error when OTP code is expired", func(t *testing.T) {
        // Arrange
        ctx := context.Background()
        code := "123456"
        otpID := "expired-otp-id"
        
        mockOTPService := mocks.NewOTPServiceMock(t)
        mockOTPService.EXPECT().
            ValidateOTP(ctx, code, otpID).
            Return(false, errors.New("OTP expired"))
        
        authService := NewAuthService(mockOTPService)
        
        // Act
        result, err := authService.Authenticate(ctx, code, otpID)
        
        // Assert
        require.Error(t, err)
        assert.Nil(t, result)
        assert.Contains(t, err.Error(), "OTP expired")
    })
}
```

## Useful Commands

### Running Tests
```bash
# Run all tests
go test ./...

# Run tests for a specific package
go test ./services

# Run tests with coverage
go test -cover ./...

# Run tests with verbose
go test -v ./services
```

### Generating Mocks
```bash
# Generate mocks for interfaces
make mocks
```

Follow these guidelines to maintain consistency and quality in project tests.