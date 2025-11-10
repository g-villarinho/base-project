package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/g-villarinho/base-project/config"
	"github.com/g-villarinho/base-project/pkg/crypto"
	"github.com/labstack/echo/v4"
	"go.uber.org/dig"
)

var (
	ErrCookieNotFound   = errors.New("cookie not found in header")
	ErrInvalidSignature = errors.New("invalid cookie signature")
)

type CookieHandlerParams struct {
	dig.In

	Config *config.Config
	Signer crypto.Signer `name:"sessionSigner"`
}

type CookieHandler interface {
	Get(ectx echo.Context) (*http.Cookie, error)
	Set(ectx echo.Context, value string, expiresAt time.Time)
	Delete(ectx echo.Context)
}

type CookieHandlerImpl struct {
	cookieName string
	isSecure   bool
	sameSite   http.SameSite
	signer     crypto.Signer
}

func NewCookieHandler(params CookieHandlerParams) CookieHandler {
	sameSite := http.SameSiteStrictMode
	switch params.Config.Session.CookieSameSite {
	case "lax":
		sameSite = http.SameSiteLaxMode
	default:
		sameSite = http.SameSiteStrictMode
	}

	return &CookieHandlerImpl{
		cookieName: params.Config.Session.CookieName,
		isSecure:   params.Config.Session.CookieSecure,
		sameSite:   sameSite,
		signer:     params.Signer,
	}
}

func (h *CookieHandlerImpl) Get(ectx echo.Context) (*http.Cookie, error) {
	cookie, err := ectx.Cookie(h.cookieName)
	if err != nil || cookie == nil {
		return nil, ErrCookieNotFound
	}

	if cookie.Value == "" {
		return nil, ErrCookieNotFound
	}

	originalValue, err := h.signer.Verify(cookie.Value)
	if err != nil {
		return nil, ErrInvalidSignature
	}

	cookie.Value = originalValue
	return cookie, nil
}

func (h *CookieHandlerImpl) Set(ectx echo.Context, value string, expiresAt time.Time) {
	maxAge := int(time.Until(expiresAt).Seconds())

	signedValue := h.signer.Sign(value)

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

func (h *CookieHandlerImpl) Delete(ectx echo.Context) {
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
