package http

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/g-villarinho/base-project/internal/mocks"
	"github.com/g-villarinho/base-project/pkg/validation"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAuthHandler_RegisterAccount(t *testing.T) {
	t.Run("should register account successfully when payload is valid", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		payload := `{"name": "João Silva", "email": "joao@example.com", "password": "senha12345"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("RegisterAccount", mock.Anything, "João Silva", "joao@example.com", "senha12345").Return(nil)

		err := handler.RegisterAccount(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusCreated, rec.Code)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return bad request when payload is invalid JSON", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		payload := `{invalid json}`

		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.RegisterAccount(c)

		assert.Equal(t, echo.ErrBadRequest, err)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return validation error when email is invalid", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		payload := `{"name": "João Silva", "email": "invalid-email", "password": "senha12345"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.RegisterAccount(c)

		assert.Error(t, err)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return conflict when email already exists", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		payload := `{"name": "João Silva", "email": "joao@example.com", "password": "senha12345"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("RegisterAccount", mock.Anything, "João Silva", "joao@example.com", "senha12345").Return(domain.ErrEmailAlreadyExists)

		err := handler.RegisterAccount(c)

		assert.NotNil(t, err)
		if httpErr, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusConflict, httpErr.Code)
		}
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return internal server error when service fails", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		payload := `{"name": "João Silva", "email": "joao@example.com", "password": "senha12345"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("RegisterAccount", mock.Anything, "João Silva", "joao@example.com", "senha12345").Return(errors.New("database error"))

		err := handler.RegisterAccount(c)

		assert.Equal(t, echo.ErrInternalServerError, err)
		mockAuthService.AssertExpectations(t)
	})
}

func TestAuthHandler_VerifyEmail(t *testing.T) {
	t.Run("should verify email successfully when token is valid", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		token := "valid-token-123"
		session := &domain.Session{
			ID:        uuid.New(),
			Token:     "session-token",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/verify-email?token="+token, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("VerifyEmail", mock.Anything, mock.MatchedBy(func(input interface{}) bool {
			return true
		})).Return(session, nil)
		mockCookieHandler.On("Set", c, session.Token, session.ExpiresAt).Return()

		err := handler.VerifyEmail(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockAuthService.AssertExpectations(t)
		mockCookieHandler.AssertExpectations(t)
	})

	t.Run("should return bad request when token is missing", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/verify-email", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.VerifyEmail(c)

		assert.Error(t, err)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return bad request when verification not found", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		token := "valid-token-123"

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/verify-email?token="+token, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("VerifyEmail", mock.Anything, mock.MatchedBy(func(input interface{}) bool {
			return true
		})).Return((*domain.Session)(nil), domain.ErrVerificationNotFound)

		err := handler.VerifyEmail(c)

		assert.Equal(t, echo.ErrBadRequest, err)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return bad request when verification is invalid", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		token := "valid-token-123"

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/verify-email?token="+token, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("VerifyEmail", mock.Anything, mock.MatchedBy(func(input interface{}) bool {
			return true
		})).Return((*domain.Session)(nil), domain.ErrInvalidVerification)

		err := handler.VerifyEmail(c)

		assert.NotNil(t, err)
		if httpErr, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusBadRequest, httpErr.Code)
		}
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return internal server error when service fails", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		token := "valid-token-123"

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/verify-email?token="+token, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("VerifyEmail", mock.Anything, mock.MatchedBy(func(input interface{}) bool {
			return true
		})).Return((*domain.Session)(nil), errors.New("database error"))

		err := handler.VerifyEmail(c)

		assert.Equal(t, echo.ErrInternalServerError, err)
		mockAuthService.AssertExpectations(t)
	})
}

func TestAuthHandler_Login(t *testing.T) {
	t.Run("should login successfully when credentials are valid", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		payload := `{"email": "joao@example.com", "password": "senha12345"}`
		session := &domain.Session{
			ID:        uuid.New(),
			Token:     "session-token",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("Login", mock.Anything, mock.MatchedBy(func(input interface{}) bool {
			return true
		})).Return(session, nil)
		mockCookieHandler.On("Set", c, session.Token, session.ExpiresAt).Return()

		err := handler.Login(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockAuthService.AssertExpectations(t)
		mockCookieHandler.AssertExpectations(t)
	})

	t.Run("should return unauthorized when credentials are invalid", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		payload := `{"email": "joao@example.com", "password": "wrongpassword"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("Login", mock.Anything, mock.Anything).Return((*domain.Session)(nil), domain.ErrInvalidCredentials)

		err := handler.Login(c)

		assert.NotNil(t, err)
		if httpErr, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
		}
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return forbidden when user is blocked", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		payload := `{"email": "joao@example.com", "password": "senha12345"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("Login", mock.Anything, mock.Anything).Return((*domain.Session)(nil), domain.ErrUserBlocked)

		err := handler.Login(c)

		assert.NotNil(t, err)
		if httpErr, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusForbidden, httpErr.Code)
		}
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return forbidden when email is not verified", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		payload := `{"email": "joao@example.com", "password": "senha12345"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("Login", mock.Anything, mock.Anything).Return((*domain.Session)(nil), domain.ErrEmailNotVerified)

		err := handler.Login(c)

		assert.NotNil(t, err)
		if httpErr, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusForbidden, httpErr.Code)
		}
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return internal server error when service fails", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		payload := `{"email": "joao@example.com", "password": "senha12345"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("Login", mock.Anything, mock.Anything).Return((*domain.Session)(nil), errors.New("database error"))

		err := handler.Login(c)

		assert.Equal(t, echo.ErrInternalServerError, err)
		mockAuthService.AssertExpectations(t)
	})
}

func TestAuthHandler_Logout(t *testing.T) {
	t.Run("should logout successfully", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/logout", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockCookieHandler.On("Delete", c).Return()

		err := handler.Logout(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockCookieHandler.AssertExpectations(t)
	})
}

func TestAuthHandler_UpdatePassword(t *testing.T) {
	t.Run("should update password successfully when current password is correct", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		userID := uuid.New()
		payload := `{"current_password": "senha12345", "new_password": "novasenha123"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPut, "/password", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		SetUserID(c, userID)

		mockAuthService.On("UpdatePassword", mock.Anything, userID, "senha12345", "novasenha123").Return(nil)

		err := handler.UpdatePassword(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return not found when user does not exist", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		userID := uuid.New()
		payload := `{"current_password": "senha12345", "new_password": "novasenha123"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPut, "/password", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		SetUserID(c, userID)

		mockAuthService.On("UpdatePassword", mock.Anything, userID, "senha12345", "novasenha123").Return(domain.ErrUserNotFound)

		err := handler.UpdatePassword(c)

		assert.NotNil(t, err)
		if httpErr, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusNotFound, httpErr.Code)
		}
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return unauthorized when current password is wrong", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		userID := uuid.New()
		payload := `{"current_password": "wrongpassword", "new_password": "novasenha123"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPut, "/password", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		SetUserID(c, userID)

		mockAuthService.On("UpdatePassword", mock.Anything, userID, "wrongpassword", "novasenha123").Return(domain.ErrPasswordMismatch)

		err := handler.UpdatePassword(c)

		assert.NotNil(t, err)
		if httpErr, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
		}
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return internal server error when service fails", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		userID := uuid.New()
		payload := `{"current_password": "senha12345", "new_password": "novasenha123"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPut, "/password", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		SetUserID(c, userID)

		mockAuthService.On("UpdatePassword", mock.Anything, userID, "senha12345", "novasenha123").Return(errors.New("database error"))

		err := handler.UpdatePassword(c)

		assert.Equal(t, echo.ErrInternalServerError, err)
		mockAuthService.AssertExpectations(t)
	})
}

func TestAuthHandler_RequestResetPassword(t *testing.T) {
	t.Run("should request password reset successfully when user exists", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		payload := `{"email": "joao@example.com"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/forgot-password", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("RequestPasswordReset", mock.Anything, "joao@example.com").Return(nil)

		err := handler.RequestResetPassword(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return ok even when user not found to prevent enumeration", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		payload := `{"email": "notfound@example.com"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/forgot-password", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("RequestPasswordReset", mock.Anything, "notfound@example.com").Return(domain.ErrUserNotFound)

		err := handler.RequestResetPassword(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return internal server error when service fails", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		payload := `{"email": "joao@example.com"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/forgot-password", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("RequestPasswordReset", mock.Anything, "joao@example.com").Return(errors.New("database error"))

		err := handler.RequestResetPassword(c)

		assert.Equal(t, echo.ErrInternalServerError, err)
		mockAuthService.AssertExpectations(t)
	})
}

func TestAuthHandler_ConfirmResetPassword(t *testing.T) {
	t.Run("should reset password successfully when token is valid", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		token := "valid-token-123"
		payload := `{"new_password": "novasenha123"}`
		session := &domain.Session{
			ID:        uuid.New(),
			Token:     "session-token",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/reset-password?token="+token, strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("ResetPassword", mock.Anything, token, "novasenha123").Return(session, nil)
		mockCookieHandler.On("Set", c, session.Token, session.ExpiresAt).Return()

		err := handler.ConfirmResetPassword(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockAuthService.AssertExpectations(t)
		mockCookieHandler.AssertExpectations(t)
	})

	t.Run("should return bad request when payload is invalid JSON", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		payload := `{invalid json}`

		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/reset-password", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.ConfirmResetPassword(c)

		assert.Equal(t, echo.ErrBadRequest, err)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return bad request when verification not found", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		token := "valid-token-123"
		payload := `{"new_password": "novasenha123"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/reset-password?token="+token, strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("ResetPassword", mock.Anything, token, "novasenha123").Return((*domain.Session)(nil), domain.ErrVerificationNotFound)

		err := handler.ConfirmResetPassword(c)

		assert.Equal(t, echo.ErrBadRequest, err)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return bad request when verification is invalid", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		token := "valid-token-123"
		payload := `{"new_password": "novasenha123"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/reset-password?token="+token, strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("ResetPassword", mock.Anything, token, "novasenha123").Return((*domain.Session)(nil), domain.ErrInvalidVerification)

		err := handler.ConfirmResetPassword(c)

		assert.NotNil(t, err)
		if httpErr, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusBadRequest, httpErr.Code)
		}
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return internal server error when service fails", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		token := "valid-token-123"
		payload := `{"new_password": "novasenha123"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/reset-password?token="+token, strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("ResetPassword", mock.Anything, token, "novasenha123").Return((*domain.Session)(nil), errors.New("database error"))

		err := handler.ConfirmResetPassword(c)

		assert.Equal(t, echo.ErrInternalServerError, err)
		mockAuthService.AssertExpectations(t)
	})
}

func TestAuthHandler_RequestChangeEmail(t *testing.T) {
	t.Run("should request email change successfully when new email is valid", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		userID := uuid.New()
		payload := `{"new_email": "newemail@example.com"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/change-email", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		SetUserID(c, userID)

		mockAuthService.On("RequestChangeEmail", mock.Anything, userID, "newemail@example.com").Return(nil)

		err := handler.RequestChangeEmail(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return conflict when email is already in use", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		userID := uuid.New()
		payload := `{"new_email": "existing@example.com"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/change-email", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		SetUserID(c, userID)

		mockAuthService.On("RequestChangeEmail", mock.Anything, userID, "existing@example.com").Return(domain.ErrEmailInUse)

		err := handler.RequestChangeEmail(c)

		assert.NotNil(t, err)
		if httpErr, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusConflict, httpErr.Code)
		}
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return not found when user does not exist", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		userID := uuid.New()
		payload := `{"new_email": "newemail@example.com"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/change-email", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		SetUserID(c, userID)

		mockAuthService.On("RequestChangeEmail", mock.Anything, userID, "newemail@example.com").Return(domain.ErrUserNotFound)

		err := handler.RequestChangeEmail(c)

		assert.NotNil(t, err)
		if httpErr, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusNotFound, httpErr.Code)
		}
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return bad request when email is the same", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		userID := uuid.New()
		payload := `{"new_email": "same@example.com"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/change-email", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		SetUserID(c, userID)

		mockAuthService.On("RequestChangeEmail", mock.Anything, userID, "same@example.com").Return(domain.ErrEmailIsTheSame)

		err := handler.RequestChangeEmail(c)

		assert.NotNil(t, err)
		if httpErr, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusBadRequest, httpErr.Code)
		}
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return internal server error when service fails", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		userID := uuid.New()
		payload := `{"new_email": "newemail@example.com"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/change-email", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		SetUserID(c, userID)

		mockAuthService.On("RequestChangeEmail", mock.Anything, userID, "newemail@example.com").Return(errors.New("database error"))

		err := handler.RequestChangeEmail(c)

		assert.Equal(t, echo.ErrInternalServerError, err)
		mockAuthService.AssertExpectations(t)
	})
}

func TestAuthHandler_ConfirmChangeEmail(t *testing.T) {
	t.Run("should confirm email change successfully when token is valid", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		token := "valid-token-123"

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/confirm-change-email?token="+token, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("ChangeEmail", mock.Anything, token).Return(nil)

		err := handler.ConfirmChangeEmail(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return validation error when token is missing", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/confirm-change-email", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.ConfirmChangeEmail(c)

		assert.Error(t, err)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return bad request when verification not found", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		token := "valid-token-123"

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/confirm-change-email?token="+token, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("ChangeEmail", mock.Anything, token).Return(domain.ErrVerificationNotFound)

		err := handler.ConfirmChangeEmail(c)

		assert.Equal(t, echo.ErrBadRequest, err)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return bad request when verification is invalid", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		token := "valid-token-123"

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/confirm-change-email?token="+token, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("ChangeEmail", mock.Anything, token).Return(domain.ErrInvalidVerification)

		err := handler.ConfirmChangeEmail(c)

		assert.NotNil(t, err)
		if httpErr, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusBadRequest, httpErr.Code)
		}
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return not found when user does not exist", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		token := "valid-token-123"

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/confirm-change-email?token="+token, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("ChangeEmail", mock.Anything, token).Return(domain.ErrUserNotFound)

		err := handler.ConfirmChangeEmail(c)

		assert.NotNil(t, err)
		if httpErr, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusNotFound, httpErr.Code)
		}
		mockAuthService.AssertExpectations(t)
	})

	t.Run("should return internal server error when service fails", func(t *testing.T) {
		mockAuthService := mocks.NewAuthServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewAuthHandler(mockAuthService, mockCookieHandler)

		token := "valid-token-123"

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPost, "/confirm-change-email?token="+token, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockAuthService.On("ChangeEmail", mock.Anything, token).Return(errors.New("database error"))

		err := handler.ConfirmChangeEmail(c)

		assert.Equal(t, echo.ErrInternalServerError, err)
		mockAuthService.AssertExpectations(t)
	})
}
