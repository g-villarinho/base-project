package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/g-villarinho/base-project/config"
	"github.com/g-villarinho/base-project/internal/service"
	"github.com/labstack/echo/v4"
)

var (
	ErrCookieNotFound   = errors.New("cookie not found in header")
	ErrInvalidSignature = errors.New("invalid cookie signature")
)

type CookieHandler interface {
	Get(ectx echo.Context) (*http.Cookie, error)
	Set(ectx echo.Context, value string, expiresAt time.Time)
	Delete(ectx echo.Context)
}

type cookieHandler struct {
	cookieName    string
	isSecure      bool
	sameSite      http.SameSite
	cookieService service.CookieService
}

func NewCookieHandler(config *config.Config, cookieService service.CookieService) CookieHandler {
	sameSite := http.SameSiteStrictMode
	switch config.Session.CookieSameSite {
	case "lax":
		sameSite = http.SameSiteLaxMode
	default:
		sameSite = http.SameSiteStrictMode
	}

	return &cookieHandler{
		cookieName:    config.Session.CookieName,
		isSecure:      config.Session.CookieSecure,
		sameSite:      sameSite,
		cookieService: cookieService,
	}
}

func (h *cookieHandler) Get(ectx echo.Context) (*http.Cookie, error) {
	cookie, err := ectx.Cookie(h.cookieName)
	if err != nil || cookie == nil {
		return nil, ErrCookieNotFound
	}

	if cookie.Value == "" {
		return nil, ErrCookieNotFound
	}

	originalValue, err := h.cookieService.Verify(ectx.Request().Context(), cookie.Value)
	if err != nil {
		return nil, ErrInvalidSignature
	}

	cookie.Value = originalValue
	return cookie, nil
}

func (h *cookieHandler) Set(ectx echo.Context, value string, expiresAt time.Time) {
	maxAge := int(time.Until(expiresAt).Seconds())

	signedValue := h.cookieService.Sign(ectx.Request().Context(), value)

	cookie := &http.Cookie{
		Name:     h.cookieName,
		Value:    signedValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.isSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	}

	ectx.SetCookie(cookie)
}

func (h *cookieHandler) Delete(ectx echo.Context) {
	cookie := &http.Cookie{
		Name:     h.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.isSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	}

	ectx.SetCookie(cookie)
}
