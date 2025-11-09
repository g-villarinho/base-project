package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/g-villarinho/base-project/internal/domain"
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
