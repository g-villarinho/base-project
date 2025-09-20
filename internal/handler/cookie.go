package handler

import (
	"net/http"
	"time"

	"github.com/g-villarinho/user-demo/config"
	"github.com/labstack/echo/v4"
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
	sessionSecret string
}

func NewCookieHandler(config *config.Config) CookieHandler {
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
		sessionSecret: config.Session.Secret,
	}
}

func (h *cookieHandler) Get(ectx echo.Context) (*http.Cookie, error) {
	cookie, err := ectx.Cookie(h.cookieName)
	if err != nil {
		return nil, err
	}

	return cookie, nil
}

func (h *cookieHandler) Set(ectx echo.Context, value string, expiresAt time.Time) {
	maxAge := int(time.Until(expiresAt).Seconds())

	cookie := &http.Cookie{
		Name:     h.cookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
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
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	}

	ectx.SetCookie(cookie)
}
