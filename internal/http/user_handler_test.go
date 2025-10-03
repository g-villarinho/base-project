package http

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/g-villarinho/base-project/internal/mocks"
	"github.com/g-villarinho/base-project/pkg/validation"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestUserHandler_UpdateProfile(t *testing.T) {
	t.Run("should update profile successfully when valid payload and user exists", func(t *testing.T) {
		mockUserService := mocks.NewUserServiceMock(t)
		handler := NewUserHandler(mockUserService)

		userID := uuid.New()
		payload := `{"name": "João Silva"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPut, "/profile", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		SetUserID(c, userID)

		mockUserService.On("UpdateUser", mock.Anything, userID, "João Silva").Return(nil)

		err := handler.UpdateProfile(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockUserService.AssertExpectations(t)
	})

	t.Run("should return bad request when payload is invalid JSON", func(t *testing.T) {
		mockUserService := mocks.NewUserServiceMock(t)
		handler := NewUserHandler(mockUserService)

		userID := uuid.New()
		payload := `{invalid json}`

		e := echo.New()
		req := httptest.NewRequest(http.MethodPut, "/profile", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		SetUserID(c, userID)

		err := handler.UpdateProfile(c)

		assert.Equal(t, echo.ErrBadRequest, err)
		mockUserService.AssertExpectations(t)
	})

	t.Run("should return validation error when name is empty", func(t *testing.T) {
		mockUserService := mocks.NewUserServiceMock(t)
		handler := NewUserHandler(mockUserService)

		userID := uuid.New()
		payload := `{"name": ""}`

		e := echo.New()
		validator := validation.NewValidator()
		e.Validator = validator
		req := httptest.NewRequest(http.MethodPut, "/profile", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		SetUserID(c, userID)

		err := handler.UpdateProfile(c)

		assert.Error(t, err)
		mockUserService.AssertExpectations(t)
	})

	t.Run("should return not found when user does not exist", func(t *testing.T) {
		mockUserService := mocks.NewUserServiceMock(t)
		handler := NewUserHandler(mockUserService)

		userID := uuid.New()
		payload := `{"name": "João Silva"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPut, "/profile", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		SetUserID(c, userID)

		mockUserService.On("UpdateUser", mock.Anything, userID, "João Silva").Return(domain.ErrUserNotFound)

		err := handler.UpdateProfile(c)

		assert.NotNil(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusNotFound, httpErr.Code)
		assert.Equal(t, domain.ErrUserNotFound.Error(), httpErr.Message)
		mockUserService.AssertExpectations(t)
	})

	t.Run("should return internal server error when service fails", func(t *testing.T) {
		mockUserService := mocks.NewUserServiceMock(t)
		handler := NewUserHandler(mockUserService)

		userID := uuid.New()
		payload := `{"name": "João Silva"}`

		e := echo.New()
		e.Validator = validation.NewValidator()
		req := httptest.NewRequest(http.MethodPut, "/profile", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		SetUserID(c, userID)

		mockUserService.On("UpdateUser", mock.Anything, userID, "João Silva").Return(errors.New("database error"))

		err := handler.UpdateProfile(c)

		assert.Equal(t, echo.ErrInternalServerError, err)
		mockUserService.AssertExpectations(t)
	})
}

func TestUserHandler_GetProfile(t *testing.T) {
	t.Run("should return profile successfully when user exists", func(t *testing.T) {
		mockUserService := mocks.NewUserServiceMock(t)
		handler := NewUserHandler(mockUserService)

		userID := uuid.New()
		user := &domain.User{
			ID:    userID,
			Name:  "João Silva",
			Email: "joao@example.com",
		}

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/profile", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		SetUserID(c, userID)

		mockUserService.On("GetUser", mock.Anything, userID).Return(user, nil)

		err := handler.GetProfile(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "joao@example.com")
		assert.Contains(t, rec.Body.String(), "João Silva")
		mockUserService.AssertExpectations(t)
	})

	t.Run("should return not found when user does not exist", func(t *testing.T) {
		mockUserService := mocks.NewUserServiceMock(t)
		handler := NewUserHandler(mockUserService)

		userID := uuid.New()

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/profile", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		SetUserID(c, userID)

		mockUserService.On("GetUser", mock.Anything, userID).Return((*domain.User)(nil), domain.ErrUserNotFound)

		err := handler.GetProfile(c)

		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusNotFound, httpErr.Code)
		assert.Equal(t, domain.ErrUserNotFound.Error(), httpErr.Message)
		mockUserService.AssertExpectations(t)
	})

	t.Run("should return internal server error when service fails", func(t *testing.T) {
		mockUserService := mocks.NewUserServiceMock(t)
		handler := NewUserHandler(mockUserService)

		userID := uuid.New()

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/profile", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		SetUserID(c, userID)

		mockUserService.On("GetUser", mock.Anything, userID).Return((*domain.User)(nil), errors.New("database error"))

		err := handler.GetProfile(c)

		assert.Equal(t, echo.ErrInternalServerError, err)
		mockUserService.AssertExpectations(t)
	})
}
