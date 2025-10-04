package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/g-villarinho/base-project/internal/domain"
	httputil "github.com/g-villarinho/base-project/internal/http"
	"github.com/g-villarinho/base-project/internal/mocks"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSessionHandler_RevokeSession(t *testing.T) {
	t.Run("should revoke session successfully when session exists and belongs to user", func(t *testing.T) {
		mockSessionService := mocks.NewSessionServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewSessionHandler(mockSessionService, mockCookieHandler)

		userID := uuid.New()
		sessionID := uuid.New()

		e := echo.New()
		req := httptest.NewRequest(http.MethodDelete, "/sessions/"+sessionID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("session_id")
		c.SetParamValues(sessionID.String())
		httputil.SetUserID(c, userID)
		httputil.SetSessionID(c, uuid.New()) // Different session

		mockSessionService.On("DeleteSessionByID", mock.Anything, userID, sessionID).Return(nil)

		err := handler.RevokeSession(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, rec.Code)
		mockSessionService.AssertExpectations(t)
		mockCookieHandler.AssertExpectations(t)
	})

	t.Run("should revoke session and delete cookie when revoking current session", func(t *testing.T) {
		mockSessionService := mocks.NewSessionServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewSessionHandler(mockSessionService, mockCookieHandler)

		userID := uuid.New()
		sessionID := uuid.New()

		e := echo.New()
		req := httptest.NewRequest(http.MethodDelete, "/sessions/"+sessionID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("session_id")
		c.SetParamValues(sessionID.String())
		httputil.SetUserID(c, userID)
		httputil.SetSessionID(c, sessionID) // Same session

		mockSessionService.On("DeleteSessionByID", mock.Anything, userID, sessionID).Return(nil)
		mockCookieHandler.On("Delete", c).Return()

		err := handler.RevokeSession(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, rec.Code)
		mockSessionService.AssertExpectations(t)
		mockCookieHandler.AssertExpectations(t)
	})

	t.Run("should return bad request when session_id is invalid UUID", func(t *testing.T) {
		mockSessionService := mocks.NewSessionServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewSessionHandler(mockSessionService, mockCookieHandler)

		userID := uuid.New()

		e := echo.New()
		req := httptest.NewRequest(http.MethodDelete, "/sessions/invalid-uuid", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("session_id")
		c.SetParamValues("invalid-uuid")
		httputil.SetUserID(c, userID)

		err := handler.RevokeSession(c)

		assert.Equal(t, echo.ErrBadRequest, err)
		mockSessionService.AssertExpectations(t)
		mockCookieHandler.AssertExpectations(t)
	})

	t.Run("should return not found when session does not exist", func(t *testing.T) {
		mockSessionService := mocks.NewSessionServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewSessionHandler(mockSessionService, mockCookieHandler)

		userID := uuid.New()
		sessionID := uuid.New()

		e := echo.New()
		req := httptest.NewRequest(http.MethodDelete, "/sessions/"+sessionID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("session_id")
		c.SetParamValues(sessionID.String())
		httputil.SetUserID(c, userID)

		mockSessionService.On("DeleteSessionByID", mock.Anything, userID, sessionID).Return(domain.ErrSessionNotFound)

		err := handler.RevokeSession(c)

		assert.NotNil(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusNotFound, httpErr.Code)
		assert.Equal(t, domain.ErrSessionNotFound.Error(), httpErr.Message)
		mockSessionService.AssertExpectations(t)
		mockCookieHandler.AssertExpectations(t)
	})

	t.Run("should return forbidden when session does not belong to user", func(t *testing.T) {
		mockSessionService := mocks.NewSessionServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewSessionHandler(mockSessionService, mockCookieHandler)

		userID := uuid.New()
		sessionID := uuid.New()

		e := echo.New()
		req := httptest.NewRequest(http.MethodDelete, "/sessions/"+sessionID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("session_id")
		c.SetParamValues(sessionID.String())
		httputil.SetUserID(c, userID)

		mockSessionService.On("DeleteSessionByID", mock.Anything, userID, sessionID).Return(domain.ErrSessionNotBelong)

		err := handler.RevokeSession(c)

		assert.NotNil(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusForbidden, httpErr.Code)
		assert.Equal(t, domain.ErrSessionNotBelong.Error(), httpErr.Message)
		mockSessionService.AssertExpectations(t)
		mockCookieHandler.AssertExpectations(t)
	})

	t.Run("should return internal server error when service fails", func(t *testing.T) {
		mockSessionService := mocks.NewSessionServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewSessionHandler(mockSessionService, mockCookieHandler)

		userID := uuid.New()
		sessionID := uuid.New()

		e := echo.New()
		req := httptest.NewRequest(http.MethodDelete, "/sessions/"+sessionID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("session_id")
		c.SetParamValues(sessionID.String())
		httputil.SetUserID(c, userID)

		mockSessionService.On("DeleteSessionByID", mock.Anything, userID, sessionID).Return(errors.New("database error"))

		err := handler.RevokeSession(c)

		assert.Equal(t, echo.ErrInternalServerError, err)
		mockSessionService.AssertExpectations(t)
		mockCookieHandler.AssertExpectations(t)
	})
}

func TestSessionHandler_RevokeAllSessions(t *testing.T) {
	t.Run("should revoke all sessions except current when include_current is false", func(t *testing.T) {
		mockSessionService := mocks.NewSessionServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewSessionHandler(mockSessionService, mockCookieHandler)

		userID := uuid.New()
		currentSessionID := uuid.New()

		e := echo.New()
		req := httptest.NewRequest(http.MethodDelete, "/sessions?include_current=false", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		httputil.SetUserID(c, userID)
		httputil.SetSessionID(c, currentSessionID)

		mockSessionService.On("DeleteSessionsByUserID", mock.Anything, userID, (*uuid.UUID)(nil)).Return(nil)

		err := handler.RevokeAllSessions(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, rec.Code)
		mockSessionService.AssertExpectations(t)
		mockCookieHandler.AssertExpectations(t)
	})

	t.Run("should revoke all sessions including current when include_current is true", func(t *testing.T) {
		mockSessionService := mocks.NewSessionServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewSessionHandler(mockSessionService, mockCookieHandler)

		userID := uuid.New()
		currentSessionID := uuid.New()

		e := echo.New()
		req := httptest.NewRequest(http.MethodDelete, "/sessions?include_current=true", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		httputil.SetUserID(c, userID)
		httputil.SetSessionID(c, currentSessionID)

		mockSessionService.On("DeleteSessionsByUserID", mock.Anything, userID, &currentSessionID).Return(nil)
		mockCookieHandler.On("Delete", c).Return()

		err := handler.RevokeAllSessions(c)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, rec.Code)
		mockSessionService.AssertExpectations(t)
		mockCookieHandler.AssertExpectations(t)
	})

	t.Run("should return bad request when payload is invalid", func(t *testing.T) {
		mockSessionService := mocks.NewSessionServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewSessionHandler(mockSessionService, mockCookieHandler)

		userID := uuid.New()
		payload := `{invalid json}`

		e := echo.New()
		req := httptest.NewRequest(http.MethodDelete, "/sessions", strings.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		httputil.SetUserID(c, userID)

		err := handler.RevokeAllSessions(c)

		assert.Equal(t, echo.ErrBadRequest, err)
		mockSessionService.AssertExpectations(t)
		mockCookieHandler.AssertExpectations(t)
	})

	t.Run("should return internal server error when service fails", func(t *testing.T) {
		mockSessionService := mocks.NewSessionServiceMock(t)
		mockCookieHandler := mocks.NewCookieHandlerMock(t)
		handler := NewSessionHandler(mockSessionService, mockCookieHandler)

		userID := uuid.New()

		e := echo.New()
		req := httptest.NewRequest(http.MethodDelete, "/sessions", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		httputil.SetUserID(c, userID)

		mockSessionService.On("DeleteSessionsByUserID", mock.Anything, userID, (*uuid.UUID)(nil)).Return(errors.New("database error"))

		err := handler.RevokeAllSessions(c)

		assert.Equal(t, echo.ErrInternalServerError, err)
		mockSessionService.AssertExpectations(t)
		mockCookieHandler.AssertExpectations(t)
	})
}
