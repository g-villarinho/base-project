package handler

import (
	"errors"
	"net/http"

	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/g-villarinho/base-project/internal/echoctx"
	"github.com/g-villarinho/base-project/internal/model"
	"github.com/g-villarinho/base-project/internal/service"
	"github.com/labstack/echo/v4"
)

type AuthHandler struct {
	authService   service.AuthService
	cookieHandler CookieHandler
}

func NewAuthHandler(
	authService service.AuthService,
	cookieHandler CookieHandler,
) *AuthHandler {
	return &AuthHandler{
		authService:   authService,
		cookieHandler: cookieHandler,
	}
}

func (h *AuthHandler) RegisterAccount(c echo.Context) error {
	var payload model.RegisterAccountPayload
	if err := c.Bind(&payload); err != nil {
		return echo.ErrBadRequest
	}

	if err := c.Validate(payload); err != nil {
		return err
	}

	err := h.authService.RegisterAccount(c.Request().Context(), payload.Name, payload.Email, payload.Password)
	if err != nil {
		if errors.Is(err, domain.ErrEmailAlreadyExists) {
			return echo.NewHTTPError(http.StatusConflict, err.Error())
		}

		return echo.ErrInternalServerError
	}

	return c.NoContent(http.StatusCreated)
}

func (h *AuthHandler) VerifyEmail(c echo.Context) error {
	var payload model.VerifyEmailPayload

	// Bind query params
	if err := echo.QueryParamsBinder(c).String("token", &payload.Token).BindError(); err != nil {
		return echo.ErrBadRequest
	}

	if err := c.Validate(payload); err != nil {
		return err
	}

	input := model.VerifyEmailInput{
		Token:      payload.Token,
		IPAddress:  c.Request().Header.Get("X-Real-IP"),
		DeviceName: c.Request().Header.Get("X-Device-Name"),
		UserAgent:  c.Request().Header.Get("User-Agent"),
	}

	session, err := h.authService.VerifyEmail(c.Request().Context(), input)
	if err != nil {
		if errors.Is(err, domain.ErrVerificationNotFound) {
			return echo.ErrBadRequest
		}

		if errors.Is(err, domain.ErrInvalidVerification) {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		return echo.ErrInternalServerError
	}

	h.cookieHandler.Set(c, session.Token, session.ExpiresAt)
	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) Login(c echo.Context) error {
	var payload model.LoginPayload
	if err := c.Bind(&payload); err != nil {
		return echo.ErrBadRequest
	}

	if err := c.Validate(payload); err != nil {
		return err
	}

	input := model.LoginInput{
		Email:      payload.Email,
		Password:   payload.Password,
		IPAddress:  c.Request().Header.Get("X-Real-IP"),
		DeviceName: c.Request().Header.Get("X-Device-Name"),
		UserAgent:  c.Request().Header.Get("User-Agent"),
	}

	session, err := h.authService.Login(c.Request().Context(), input)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) {
			return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
		}

		if errors.Is(err, domain.ErrUserBlocked) {
			return echo.NewHTTPError(http.StatusForbidden, err.Error())
		}

		if errors.Is(err, domain.ErrEmailNotVerified) {
			return echo.NewHTTPError(http.StatusForbidden, err.Error())
		}

		return echo.ErrInternalServerError
	}

	h.cookieHandler.Set(c, session.Token, session.ExpiresAt)
	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) Logout(c echo.Context) error {
	h.cookieHandler.Delete(c)
	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) UpdatePassword(c echo.Context) error {
	var payload model.UpdatePasswordPayload
	if err := c.Bind(&payload); err != nil {
		return echo.ErrBadRequest
	}

	if err := c.Validate(payload); err != nil {
		return err
	}

	err := h.authService.UpdatePassword(c.Request().Context(), echoctx.GetUserID(c), payload.CurrentPassword, payload.NewPassword)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}

		if errors.Is(err, domain.ErrPasswordMismatch) {
			return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
		}

		return echo.ErrInternalServerError
	}

	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) RequestResetPassword(c echo.Context) error {
	var payload model.ForgotPasswordPayload
	if err := c.Bind(&payload); err != nil {
		return echo.ErrBadRequest
	}

	if err := c.Validate(payload); err != nil {
		return err
	}

	if err := h.authService.RequestPasswordReset(c.Request().Context(), payload.Email); err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			// To prevent user enumeration, we return 200 OK even if the user is not found.
			return c.NoContent(http.StatusOK)
		}

		return echo.ErrInternalServerError
	}

	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) ConfirmResetPassword(c echo.Context) error {
	var payload model.ResetPasswordPayload

	// Bind query params
	if err := echo.QueryParamsBinder(c).String("token", &payload.Token).BindError(); err != nil {
		return echo.ErrBadRequest
	}

	// Bind JSON body
	if err := c.Bind(&payload); err != nil {
		return echo.ErrBadRequest
	}

	if err := c.Validate(payload); err != nil {
		return err
	}

	session, err := h.authService.ResetPassword(c.Request().Context(), payload.Token, payload.NewPassword)
	if err != nil {
		if errors.Is(err, domain.ErrVerificationNotFound) {
			return echo.ErrBadRequest
		}

		if errors.Is(err, domain.ErrInvalidVerification) {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		return echo.ErrInternalServerError
	}

	h.cookieHandler.Set(c, session.Token, session.ExpiresAt)
	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) RequestChangeEmail(c echo.Context) error {
	var payload model.RequestEmailChangePayload
	if err := c.Bind(&payload); err != nil {
		return echo.ErrBadRequest
	}

	if err := c.Validate(payload); err != nil {
		return err
	}

	err := h.authService.RequestChangeEmail(c.Request().Context(), echoctx.GetUserID(c), payload.NewEmail)
	if err != nil {
		if errors.Is(err, domain.ErrEmailInUse) {
			return echo.NewHTTPError(http.StatusConflict, err.Error())
		}

		if errors.Is(err, domain.ErrUserNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}

		if errors.Is(err, domain.ErrEmailIsTheSame) {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		return echo.ErrInternalServerError
	}

	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) ConfirmChangeEmail(c echo.Context) error {
	var payload model.ConfirmEmailChangePayload

	// Bind query params
	if err := echo.QueryParamsBinder(c).String("token", &payload.Token).BindError(); err != nil {
		return echo.ErrBadRequest
	}

	if err := c.Validate(payload); err != nil {
		return err
	}

	err := h.authService.ChangeEmail(c.Request().Context(), payload.Token)
	if err != nil {
		if errors.Is(err, domain.ErrVerificationNotFound) {
			return echo.ErrBadRequest
		}

		if errors.Is(err, domain.ErrInvalidVerification) {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		if errors.Is(err, domain.ErrUserNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}

		return echo.ErrInternalServerError
	}

	return c.NoContent(http.StatusOK)
}
