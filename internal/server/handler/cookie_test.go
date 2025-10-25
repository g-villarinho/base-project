package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/g-villarinho/base-project/config"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestCookieHandler_Set(t *testing.T) {
	t.Run("should set cookie with correct attributes when called", func(t *testing.T) {
		cfg := &config.Config{
			Session: config.Session{
				CookieName:     "test_session",
				CookieSecure:   true,
				CookieSameSite: "strict",
				Secret:         "test-secret-key",
			},
		}
		handler := NewCookieHandler(cfg)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		value := "test-token-123"
		expiresAt := time.Now().Add(1 * time.Hour)

		handler.Set(c, value, expiresAt)

		cookies := rec.Result().Cookies()
		assert.Len(t, cookies, 1)
		assert.Equal(t, "test_session", cookies[0].Name)
		assert.Contains(t, cookies[0].Value, "test-token-123")
		assert.True(t, cookies[0].HttpOnly)
		assert.True(t, cookies[0].Secure)
		assert.Equal(t, http.SameSiteStrictMode, cookies[0].SameSite)
		assert.Equal(t, "/", cookies[0].Path)
		assert.Greater(t, cookies[0].MaxAge, 0)
	})

	t.Run("should set cookie with lax SameSite when configured", func(t *testing.T) {
		cfg := &config.Config{
			Session: config.Session{
				CookieName:     "test_session",
				CookieSecure:   false,
				CookieSameSite: "lax",
				Secret:         "test-secret-key",
			},
		}
		handler := NewCookieHandler(cfg)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		value := "test-token-123"
		expiresAt := time.Now().Add(1 * time.Hour)

		handler.Set(c, value, expiresAt)

		cookies := rec.Result().Cookies()
		assert.Len(t, cookies, 1)
		assert.False(t, cookies[0].Secure)
	})

	t.Run("should sign cookie value with HMAC signature", func(t *testing.T) {
		cfg := &config.Config{
			Session: config.Session{
				CookieName:     "test_session",
				CookieSecure:   true,
				CookieSameSite: "strict",
				Secret:         "test-secret-key",
			},
		}
		handler := NewCookieHandler(cfg)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		value := "test-token-123"
		expiresAt := time.Now().Add(1 * time.Hour)

		handler.Set(c, value, expiresAt)

		cookies := rec.Result().Cookies()
		assert.Len(t, cookies, 1)
		// Cookie value should contain a dot separating value and signature
		assert.Contains(t, cookies[0].Value, ".")
		parts := len(cookies[0].Value) > len(value)
		assert.True(t, parts)
	})
}

func TestCookieHandler_Get(t *testing.T) {
	t.Run("should get cookie successfully when signature is valid", func(t *testing.T) {
		cfg := &config.Config{
			Session: config.Session{
				CookieName:     "test_session",
				CookieSecure:   true,
				CookieSameSite: "strict",
				Secret:         "test-secret-key",
			},
		}
		handler := NewCookieHandler(cfg)

		// First set a cookie
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		value := "test-token-123"
		expiresAt := time.Now().Add(1 * time.Hour)
		handler.Set(c, value, expiresAt)

		// Then get the cookie
		cookies := rec.Result().Cookies()
		req2 := httptest.NewRequest(http.MethodGet, "/", nil)
		req2.AddCookie(cookies[0])
		rec2 := httptest.NewRecorder()
		c2 := e.NewContext(req2, rec2)

		cookie, err := handler.Get(c2)

		assert.NoError(t, err)
		assert.NotNil(t, cookie)
		assert.Equal(t, "test-token-123", cookie.Value)
	})

	t.Run("should return error when cookie does not exist", func(t *testing.T) {
		cfg := &config.Config{
			Session: config.Session{
				CookieName:     "test_session",
				CookieSecure:   true,
				CookieSameSite: "strict",
				Secret:         "test-secret-key",
			},
		}
		handler := NewCookieHandler(cfg)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		cookie, err := handler.Get(c)

		assert.Error(t, err)
		assert.Nil(t, cookie)
	})

	t.Run("should return error when cookie signature is invalid", func(t *testing.T) {
		cfg := &config.Config{
			Session: config.Session{
				CookieName:     "test_session",
				CookieSecure:   true,
				CookieSameSite: "strict",
				Secret:         "test-secret-key",
			},
		}
		handler := NewCookieHandler(cfg)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		// Add cookie with invalid signature
		req.AddCookie(&http.Cookie{
			Name:  "test_session",
			Value: "test-token-123.invalidsignature",
		})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		cookie, err := handler.Get(c)

		assert.Error(t, err)
		assert.Nil(t, cookie)
		if httpErr, ok := err.(*echo.HTTPError); ok {
			assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
		}
	})

	t.Run("should return error when cookie value has no signature", func(t *testing.T) {
		cfg := &config.Config{
			Session: config.Session{
				CookieName:     "test_session",
				CookieSecure:   true,
				CookieSameSite: "strict",
				Secret:         "test-secret-key",
			},
		}
		handler := NewCookieHandler(cfg)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		// Add cookie without signature (no dot)
		req.AddCookie(&http.Cookie{
			Name:  "test_session",
			Value: "test-token-123",
		})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		cookie, err := handler.Get(c)

		assert.Error(t, err)
		assert.Nil(t, cookie)
	})
}

func TestCookieHandler_Delete(t *testing.T) {
	t.Run("should delete cookie by setting MaxAge to -1", func(t *testing.T) {
		cfg := &config.Config{
			Session: config.Session{
				CookieName:     "test_session",
				CookieSecure:   true,
				CookieSameSite: "strict",
				Secret:         "test-secret-key",
			},
		}
		handler := NewCookieHandler(cfg)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		handler.Delete(c)

		cookies := rec.Result().Cookies()
		assert.Len(t, cookies, 1)
		assert.Equal(t, "test_session", cookies[0].Name)
		assert.Equal(t, "", cookies[0].Value)
		assert.Equal(t, -1, cookies[0].MaxAge)
		assert.True(t, cookies[0].HttpOnly)
		assert.True(t, cookies[0].Secure)
		assert.Equal(t, http.SameSiteStrictMode, cookies[0].SameSite)
		assert.Equal(t, "/", cookies[0].Path)
	})
}

func TestCookieHandler_SignAndVerify(t *testing.T) {
	t.Run("should verify correctly signed cookie", func(t *testing.T) {
		cfg := &config.Config{
			Session: config.Session{
				CookieName:     "test_session",
				CookieSecure:   true,
				CookieSameSite: "strict",
				Secret:         "test-secret-key",
			},
		}
		handler := NewCookieHandler(cfg).(*cookieHandler)

		value := "test-token-123"
		signedValue := handler.signCookie(value)

		assert.True(t, handler.verifyCookie(signedValue))
		assert.Contains(t, signedValue, ".")
	})

	t.Run("should reject tampered cookie signature", func(t *testing.T) {
		cfg := &config.Config{
			Session: config.Session{
				CookieName:     "test_session",
				CookieSecure:   true,
				CookieSameSite: "strict",
				Secret:         "test-secret-key",
			},
		}
		handler := NewCookieHandler(cfg).(*cookieHandler)

		value := "test-token-123"
		signedValue := handler.signCookie(value)

		// Tamper with the value
		tamperedValue := "tampered-token." + signedValue[len("test-token-123")+1:]

		assert.False(t, handler.verifyCookie(tamperedValue))
	})

	t.Run("should reject cookie with different secret", func(t *testing.T) {
		cfg1 := &config.Config{
			Session: config.Session{
				CookieName:     "test_session",
				CookieSecure:   true,
				CookieSameSite: "strict",
				Secret:         "secret-key-1",
			},
		}
		handler1 := NewCookieHandler(cfg1).(*cookieHandler)

		cfg2 := &config.Config{
			Session: config.Session{
				CookieName:     "test_session",
				CookieSecure:   true,
				CookieSameSite: "strict",
				Secret:         "secret-key-2",
			},
		}
		handler2 := NewCookieHandler(cfg2).(*cookieHandler)

		value := "test-token-123"
		signedValue := handler1.signCookie(value)

		assert.False(t, handler2.verifyCookie(signedValue))
	})
}

func TestNewCookieHandler(t *testing.T) {
	t.Run("should create handler with strict SameSite by default", func(t *testing.T) {
		cfg := &config.Config{
			Session: config.Session{
				CookieName:     "test_session",
				CookieSecure:   true,
				CookieSameSite: "invalid",
				Secret:         "test-secret-key",
			},
		}
		handler := NewCookieHandler(cfg).(*cookieHandler)

		assert.Equal(t, http.SameSiteStrictMode, handler.sameSite)
	})

	t.Run("should create handler with lax SameSite when configured", func(t *testing.T) {
		cfg := &config.Config{
			Session: config.Session{
				CookieName:     "test_session",
				CookieSecure:   true,
				CookieSameSite: "lax",
				Secret:         "test-secret-key",
			},
		}
		handler := NewCookieHandler(cfg).(*cookieHandler)

		assert.Equal(t, http.SameSiteLaxMode, handler.sameSite)
	})

	t.Run("should create handler with correct configuration", func(t *testing.T) {
		cfg := &config.Config{
			Session: config.Session{
				CookieName:     "my_session",
				CookieSecure:   false,
				CookieSameSite: "strict",
				Secret:         "my-secret",
			},
		}
		handler := NewCookieHandler(cfg).(*cookieHandler)

		assert.Equal(t, "my_session", handler.cookieName)
		assert.False(t, handler.isSecure)
		assert.Equal(t, http.SameSiteStrictMode, handler.sameSite)
		assert.Equal(t, "my-secret", handler.sessionSecret)
	})
}
