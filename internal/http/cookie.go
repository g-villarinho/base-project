package http

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/g-villarinho/base-project/config"
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

	if !h.verifyCookie(cookie.Value) {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "invalid cookie signature")
	}

	parts := strings.Split(cookie.Value, ".")
	if len(parts) == 2 {
		cookie.Value = parts[0]
	}

	return cookie, nil
}

func (h *cookieHandler) Set(ectx echo.Context, value string, expiresAt time.Time) {
	maxAge := int(time.Until(expiresAt).Seconds())

	signedValue := h.signCookie(value)

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

func (h *cookieHandler) signCookie(value string) string {
	mac := hmac.New(sha256.New, []byte(h.sessionSecret))
	mac.Write([]byte(value))
	signature := hex.EncodeToString(mac.Sum(nil))
	return value + "." + signature
}

func (h *cookieHandler) verifyCookie(signedValue string) bool {
	parts := strings.Split(signedValue, ".")
	if len(parts) != 2 {
		return false
	}

	value, signature := parts[0], parts[1]
	expectedSignature := h.signCookie(value)
	expectedParts := strings.Split(expectedSignature, ".")

	return len(expectedParts) == 2 && hmac.Equal([]byte(signature), []byte(expectedParts[1]))
}
