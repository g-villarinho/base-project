package integration

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/g-villarinho/base-project/config"
	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/g-villarinho/base-project/internal/infra/notification"
	"github.com/g-villarinho/base-project/internal/mocks"
	"github.com/g-villarinho/base-project/internal/repository"
	"github.com/g-villarinho/base-project/internal/server"
	"github.com/g-villarinho/base-project/internal/server/handler"
	"github.com/g-villarinho/base-project/internal/server/middleware"
	"github.com/g-villarinho/base-project/internal/service"
	"github.com/g-villarinho/base-project/pkg/hash"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/mock"
	"go.uber.org/dig"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

const (
	CookieSessionName = "test-session"
)

// testServer holds the test server and its dependencies
type testServer struct {
	Echo *echo.Echo
	DB   *gorm.DB
}

// setupTestServer creates a new test server with in-memory SQLite database
// This function can be used by all integration tests to get a clean test environment
func setupTestServer(t *testing.T) *testServer {
	t.Helper()

	// Create dependency injection container
	container := dig.New()

	// Provide test configuration
	err := container.Provide(func() (*config.Config, error) {
		return &config.Config{
			Env:         config.Development,
			ShowSQLLogs: false,
			Server: config.Server{
				Port: 5001,
				Host: "localhost",
			},
			SqlLite: config.SqlLite{
				DatabaseName: ":memory:", // In-memory database for tests
				MaxConn:      10,
				MaxIdle:      5,
				MaxLifeTime:  300 * time.Second,
			},
			Security: config.Security{
				AccessTokenExpirationHours: 2 * time.Hour,
				Issuer:                     "test-api",
				Audience:                   "test-api",
			},
			RateLimit: config.RateLimit{
				MaxRequests: 100,
				Window:      1 * time.Minute,
			},
			Cors: config.Cors{
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
				AllowedHeaders: []string{"Content-Type", "Authorization"},
			},
			URL: config.URL{
				APIBaseURL: "http://localhost:5001",
				APPBaseURL: "http://localhost:5173",
			},
			Resend: config.Resend{
				APIKey:  "test-key",
				Domain:  "test.com",
				Timeout: 10 * time.Second,
			},
			Session: config.Session{
				Secret:         "test-secret-key-for-testing",
				Duration:       168 * time.Hour,
				TokenSize:      32,
				CookieName:     "test-session",
				CookieSecure:   false,
				CookieSameSite: "strict",
			},
		}, nil
	})
	if err != nil {
		t.Fatalf("Failed to provide config: %v", err)
	}

	// Provide in-memory database
	err = container.Provide(func(cfg *config.Config) (*gorm.DB, error) {
		gormConfig := &gorm.Config{
			Logger: gormLogger.Default.LogMode(gormLogger.Silent),
		}

		db, err := gorm.Open(sqlite.Open(":memory:"), gormConfig)
		if err != nil {
			return nil, err
		}

		// Run migrations
		if err := db.AutoMigrate(&domain.User{}, &domain.Verification{}, &domain.Session{}); err != nil {
			return nil, err
		}

		return db, nil
	})
	if err != nil {
		t.Fatalf("Failed to provide database: %v", err)
	}

	// Provide logger
	err = container.Provide(func() *slog.Logger {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	})
	if err != nil {
		t.Fatalf("Failed to provide logger: %v", err)
	}

	// Provide mock email notification using mockery-generated mock
	err = container.Provide(func() notification.EmailNotification {
		mockEmail := mocks.NewEmailNotificationMock(t)

		mockEmail.On("SendWelcomeEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Maybe()
		mockEmail.On("SendVerifyEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Maybe()
		mockEmail.On("SendResetPasswordEmail", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Maybe()
		mockEmail.On("SendChangeEmailNotification", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Maybe()

		return mockEmail
	})
	if err != nil {
		t.Fatalf("Failed to provide email notification: %v", err)
	}

	// Provide repositories
	err = container.Provide(repository.NewUserRepository)
	if err != nil {
		t.Fatalf("Failed to provide user repository: %v", err)
	}

	err = container.Provide(repository.NewSessionRepository)
	if err != nil {
		t.Fatalf("Failed to provide session repository: %v", err)
	}

	err = container.Provide(repository.NewVerificationRepository)
	if err != nil {
		t.Fatalf("Failed to provide verification repository: %v", err)
	}

	// Provide services
	err = container.Provide(service.NewVerificationService)
	if err != nil {
		t.Fatalf("Failed to provide verification service: %v", err)
	}

	err = container.Provide(service.NewAuthService)
	if err != nil {
		t.Fatalf("Failed to provide auth service: %v", err)
	}

	err = container.Provide(service.NewSessionService)
	if err != nil {
		t.Fatalf("Failed to provide session service: %v", err)
	}

	err = container.Provide(service.NewUserService)
	if err != nil {
		t.Fatalf("Failed to provide user service: %v", err)
	}

	// Provide handlers
	err = container.Provide(handler.NewCookieHandler)
	if err != nil {
		t.Fatalf("Failed to provide cookie handler: %v", err)
	}

	err = container.Provide(handler.NewAuthHandler)
	if err != nil {
		t.Fatalf("Failed to provide auth handler: %v", err)
	}

	err = container.Provide(handler.NewUserHandler)
	if err != nil {
		t.Fatalf("Failed to provide user handler: %v", err)
	}

	err = container.Provide(handler.NewSessionHandler)
	if err != nil {
		t.Fatalf("Failed to provide session handler: %v", err)
	}

	// Provide middleware
	err = container.Provide(middleware.NewAuthMiddleware)
	if err != nil {
		t.Fatalf("Failed to provide auth middleware: %v", err)
	}

	// Provide server
	err = container.Provide(server.NewServer)
	if err != nil {
		t.Fatalf("Failed to provide server: %v", err)
	}

	// Resolve server and database
	var e *echo.Echo
	var db *gorm.DB

	err = container.Invoke(func(echoServer *echo.Echo, database *gorm.DB) {
		e = echoServer
		db = database
	})
	if err != nil {
		t.Fatalf("Failed to resolve dependencies: %v", err)
	}

	return &testServer{
		Echo: e,
		DB:   db,
	}
}

// teardownTestServer cleans up the test server
func teardownTestServer(t *testing.T, ts *testServer) {
	t.Helper()

	if ts.DB != nil {
		sqlDB, err := ts.DB.DB()
		if err == nil {
			sqlDB.Close()
		}
	}
}

// makeRequest is a helper function to make HTTP requests in tests
func makeRequest(t *testing.T, ts *testServer, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("Failed to marshal request body: %v", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	ts.Echo.ServeHTTP(rec, req)

	return rec
}

func createTestUser(t *testing.T, ts *testServer, email, password string) *domain.User {
	t.Helper()

	hashedPassword, err := hash.HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %s", err)
	}
	user := &domain.User{
		ID:               uuid.New(),
		Name:             "Test User",
		Email:            email,
		PasswordHash:     hashedPassword,
		Status:           domain.ActiveStatus,
		CreatedAt:        time.Now().UTC(),
		EmailConfirmedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}

	result := ts.DB.Create(&user)
	if result.Error != nil {
		t.Fatalf("Failed to create test user: %v", result.Error)
	}

	return user
}

func createTestSession(t *testing.T, ts *testServer, userID uuid.UUID) *domain.Session {
	t.Helper()

	session := &domain.Session{
		ID:        uuid.New(),
		UserID:    userID,
		Token:     uuid.NewString(),
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(168 * time.Hour),
	}

	result := ts.DB.Create(&session)
	if result.Error != nil {
		t.Fatalf("Failed to create test session: %v", result.Error)
	}

	return session
}
