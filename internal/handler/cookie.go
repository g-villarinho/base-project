package handler

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

const (
	cookieName = "user:token"
)

func GetCookie(ectx echo.Context) (*http.Cookie, error) {
	cookie, err := ectx.Cookie(cookieName)
	if err != nil {
		return nil, err
	}

	return cookie, nil
}

func SetCookie(ectx echo.Context, value string, expiresAt time.Time) {
	maxAge := int(time.Until(expiresAt).Seconds())

	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	}

	ectx.SetCookie(cookie)
}

func DeleteCookie(ectx echo.Context) {
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	}

	ectx.SetCookie(cookie)
}
