package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestRegisterAccount(t *testing.T) {
	t.Run("should successfully register a new user", func(t *testing.T) {
		ts := setupTestServer(t)
		defer teardownTestServer(t, ts)

		payload := map[string]any{
			"name":     "John Doe",
			"email":    "john.doe@example.com",
			"password": "securepassword123",
		}

		rec := makeRequest(t, ts, http.MethodPost, "/auth/register", payload)

		assert.Equal(t, http.StatusCreated, rec.Code)

		var user domain.User
		result := ts.DB.Where("email = ?", "john.doe@example.com").First(&user)
		assert.NoError(t, result.Error)
		assert.Equal(t, "John Doe", user.Name)
		assert.Equal(t, "john.doe@example.com", user.Email)
		assert.Equal(t, domain.PendingStatus, user.Status)
	})

	t.Run("should return conflict when email already exists", func(t *testing.T) {
		ts := setupTestServer(t)
		defer teardownTestServer(t, ts)

		payload := map[string]any{
			"name":     "John Doe",
			"email":    "duplicate@example.com",
			"password": "securepassword123",
		}
		makeRequest(t, ts, http.MethodPost, "/auth/register", payload)

		rec := makeRequest(t, ts, http.MethodPost, "/auth/register", payload)

		assert.Equal(t, http.StatusConflict, rec.Code)

		var response map[string]any
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		assert.NoError(t, err)

		assert.NotNil(t, response)
	})

	t.Run("should return bad request for invalid JSON payload", func(t *testing.T) {
		ts := setupTestServer(t)
		defer teardownTestServer(t, ts)

		req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBufferString("invalid json"))
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()
		ts.Echo.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("should return validation error when name is missing", func(t *testing.T) {
		ts := setupTestServer(t)
		defer teardownTestServer(t, ts)

		payload := map[string]any{
			"email":    "test@example.com",
			"password": "securepassword123",
		}

		rec := makeRequest(t, ts, http.MethodPost, "/auth/register", payload)

		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)

		var response map[string]any
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.NotNil(t, response["errors"])
	})

	t.Run("should return validation error when email is missing", func(t *testing.T) {
		ts := setupTestServer(t)
		defer teardownTestServer(t, ts)

		payload := map[string]any{
			"name":     "John Doe",
			"password": "securepassword123",
		}

		rec := makeRequest(t, ts, http.MethodPost, "/auth/register", payload)

		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)

		var response map[string]any
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.NotNil(t, response["errors"])
	})

	t.Run("should return validation error when password is missing", func(t *testing.T) {
		ts := setupTestServer(t)
		defer teardownTestServer(t, ts)

		payload := map[string]any{
			"name":  "John Doe",
			"email": "test@example.com",
		}

		rec := makeRequest(t, ts, http.MethodPost, "/auth/register", payload)

		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)

		var response map[string]any
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.NotNil(t, response["errors"])
	})

	t.Run("should return validation error for invalid email format", func(t *testing.T) {
		ts := setupTestServer(t)
		defer teardownTestServer(t, ts)

		payload := map[string]any{
			"name":     "John Doe",
			"email":    "invalid-email",
			"password": "securepassword123",
		}

		rec := makeRequest(t, ts, http.MethodPost, "/auth/register", payload)

		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)

		var response map[string]any
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.NotNil(t, response["errors"])
	})

	t.Run("should return validation error when password is too short", func(t *testing.T) {
		ts := setupTestServer(t)
		defer teardownTestServer(t, ts)

		payload := map[string]any{
			"name":     "John Doe",
			"email":    "test@example.com",
			"password": "short",
		}

		rec := makeRequest(t, ts, http.MethodPost, "/auth/register", payload)

		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)

		var response map[string]any
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.NotNil(t, response["errors"])
	})
}

func TestVerifyEmail(t *testing.T) {
	t.Run("should successfully verify email with valid token", func(t *testing.T) {
		ts := setupTestServer(t)
		defer teardownTestServer(t, ts)

		user := domain.User{
			ID:           uuid.New(),
			Name:         "Test User",
			Email:        "test@example.com",
			Status:       domain.PendingStatus,
			PasswordHash: "hashedpassword",
			CreatedAt:    time.Now().UTC(),
		}
		result := ts.DB.Create(&user)
		assert.NoError(t, result.Error)

		verification := domain.Verification{
			ID:        uuid.New(),
			Flow:      domain.VerificationEmailFlow,
			Token:     "valid-token-123",
			CreatedAt: time.Now().UTC(),
			ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
			UserID:    user.ID,
		}
		result = ts.DB.Create(&verification)
		assert.NoError(t, result.Error)

		rec := makeRequest(t, ts, http.MethodGet, "/auth/verify-email?token=valid-token-123", nil)

		assert.Equal(t, http.StatusOK, rec.Code)

		var updatedUser domain.User
		result = ts.DB.Where("email = ?", "test@example.com").First(&updatedUser)
		assert.NoError(t, result.Error)
		assert.Equal(t, domain.ActiveStatus, updatedUser.Status)
		assert.True(t, updatedUser.EmailConfirmedAt.Valid)

		var deletedVerification domain.Verification
		result = ts.DB.Where("token = ?", "valid-token-123").First(&deletedVerification)
		assert.Error(t, result.Error)

		cookies := rec.Result().Cookies()
		assert.NotEmpty(t, cookies)
	})

	t.Run("should return not found for non-existent token", func(t *testing.T) {
		ts := setupTestServer(t)
		defer teardownTestServer(t, ts)

		rec := makeRequest(t, ts, http.MethodGet, "/auth/verify-email?token=non-existent-token", nil)

		assert.Equal(t, http.StatusNotFound, rec.Code)

		var response map[string]any
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["title"], "Verification token not found")
	})

	t.Run("should return bad request for expired token", func(t *testing.T) {
		ts := setupTestServer(t)
		defer teardownTestServer(t, ts)

		user := domain.User{
			ID:           uuid.New(),
			Name:         "Test User",
			Email:        "expired@example.com",
			Status:       domain.PendingStatus,
			PasswordHash: "hashedpassword",
			CreatedAt:    time.Now().UTC(),
		}
		result := ts.DB.Create(&user)
		assert.NoError(t, result.Error)

		verification := domain.Verification{
			ID:        uuid.New(),
			Flow:      domain.VerificationEmailFlow,
			Token:     "expired-token-123",
			CreatedAt: time.Now().UTC().Add(-20 * time.Minute),
			ExpiresAt: time.Now().UTC().Add(-10 * time.Minute), // Expired 10 minutes ago
			UserID:    user.ID,
		}
		result = ts.DB.Create(&verification)
		assert.NoError(t, result.Error)

		rec := makeRequest(t, ts, http.MethodGet, "/auth/verify-email?token=expired-token-123", nil)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var response map[string]any
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["title"], "The verification token is invalid or has expired")
	})

	t.Run("should return not found for already used token", func(t *testing.T) {
		ts := setupTestServer(t)
		defer teardownTestServer(t, ts)

		// Create a user with pending status
		user := domain.User{
			ID:           uuid.New(),
			Name:         "Test User",
			Email:        "used@example.com",
			Status:       domain.PendingStatus,
			PasswordHash: "hashedpassword",
			CreatedAt:    time.Now().UTC(),
		}
		result := ts.DB.Create(&user)
		assert.NoError(t, result.Error)

		// Create a verification token
		verification := domain.Verification{
			ID:        uuid.New(),
			Flow:      domain.VerificationEmailFlow,
			Token:     "used-token-123",
			CreatedAt: time.Now().UTC(),
			ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
			UserID:    user.ID,
		}
		result = ts.DB.Create(&verification)
		assert.NoError(t, result.Error)

		// Delete the token to simulate it being used
		result = ts.DB.Delete(&verification)
		assert.NoError(t, result.Error)

		rec := makeRequest(t, ts, http.MethodGet, "/auth/verify-email?token=used-token-123", nil)

		assert.Equal(t, http.StatusNotFound, rec.Code)

		var response map[string]any
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["message"], "Verification token not found")
	})

	t.Run("should return validation error when token is missing", func(t *testing.T) {
		ts := setupTestServer(t)
		defer teardownTestServer(t, ts)

		rec := makeRequest(t, ts, http.MethodGet, "/auth/verify-email", nil)

		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)

		var response map[string]any
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.NotNil(t, response["errors"])
	})

	t.Run("should return bad request for wrong flow type", func(t *testing.T) {
		ts := setupTestServer(t)
		defer teardownTestServer(t, ts)

		// Create a user
		user := domain.User{
			ID:           uuid.New(),
			Name:         "Test User",
			Email:        "wrongflow@example.com",
			Status:       domain.PendingStatus,
			PasswordHash: "hashedpassword",
			CreatedAt:    time.Now().UTC(),
		}
		result := ts.DB.Create(&user)
		assert.NoError(t, result.Error)

		// Create a verification token with wrong flow (ResetPasswordFlow instead of VerificationEmailFlow)
		verification := domain.Verification{
			ID:        uuid.New(),
			Flow:      domain.ResetPasswordFlow, // Wrong flow!
			Token:     "wrong-flow-token",
			CreatedAt: time.Now().UTC(),
			ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
			UserID:    user.ID,
		}
		result = ts.DB.Create(&verification)
		assert.NoError(t, result.Error)

		rec := makeRequest(t, ts, http.MethodGet, "/auth/verify-email?token=wrong-flow-token", nil)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var response map[string]any
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response["message"], "invalid or has expired")
	})
}
