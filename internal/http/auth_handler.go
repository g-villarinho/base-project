package http

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/g-villarinho/base-project/internal/model"
	"github.com/g-villarinho/base-project/internal/service"
	"github.com/labstack/echo/v4"
)

type AuthHandler struct {
	authService   service.AuthService
	logger        *slog.Logger
	cookieHandler CookieHandler
}

func NewAuthHandler(
	authService service.AuthService,
	logger *slog.Logger,
	cookieHandler CookieHandler,
) *AuthHandler {
	return &AuthHandler{
		authService:   authService,
		logger:        logger.With(slog.String("handler", "auth")),
		cookieHandler: cookieHandler,
	}
}

func (h *AuthHandler) RegisterAccount(c echo.Context) error {
	logger := h.logger.With(
		slog.String("method", "RegisterAccount"),
		slog.String("path", c.Request().URL.Path),
	)

	var payload model.RegisterAccountPayload
	if err := c.Bind(&payload); err != nil {
		logger.Error("bind request body", "error", err)
		return echo.ErrBadRequest
	}

	if err := c.Validate(payload); err != nil {
		logger.Error("invalid payload with validation errors")
		return err
	}

	err := h.authService.RegisterAccount(c.Request().Context(), payload.Name, payload.Email, payload.Password)
	if err != nil {
		logger.Error("register account", "error", err)

		if errors.Is(err, domain.ErrEmailAlreadyExists) {
			return echo.NewHTTPError(http.StatusConflict, err.Error())
		}

		return echo.ErrInternalServerError
	}

	return c.NoContent(http.StatusCreated)
}

func (h *AuthHandler) VerifyEmail(c echo.Context) error {
	logger := h.logger.With(
		slog.String("method", "VerifyEmail"),
		slog.String("path", c.Request().URL.Path),
	)

	var payload model.VerifyEmailPayload
	if err := c.Bind(&payload); err != nil {
		logger.Error("bind request body", "error", err)
		return echo.ErrBadRequest
	}

	if err := c.Validate(payload); err != nil {
		logger.Error("invalid payload with validation errors")
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
		logger.Error("verify email", "error", err)

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
	logger := h.logger.With(
		slog.String("method", "Login"),
		slog.String("path", c.Request().URL.Path),
	)

	var payload model.LoginPayload
	if err := c.Bind(&payload); err != nil {
		logger.Error("bind request body", "error", err)
		return echo.ErrBadRequest
	}

	if err := c.Validate(payload); err != nil {
		logger.Error("invalid payload with validation errors")
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
		logger.Error("login", "error", err)

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
	logger := h.logger.With(
		slog.String("method", "UpdatePassword"),
		slog.String("path", c.Request().URL.Path),
	)

	var payload model.UpdatePasswordPayload
	if err := c.Bind(&payload); err != nil {
		logger.Error("bind request body", "error", err)
		return echo.ErrBadRequest
	}

	if err := c.Validate(payload); err != nil {
		logger.Error("invalid payload with validation errors")
		return err
	}

	err := h.authService.UpdatePassword(c.Request().Context(), GetUserID(c), payload.CurrentPassword, payload.NewPassword)
	if err != nil {
		logger.Error("update password", "error", err)

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
	logger := h.logger.With(
		slog.String("method", "RequestResetPassword"),
		slog.String("path", c.Request().URL.Path),
	)

	var payload model.ForgotPasswordPayload
	if err := c.Bind(&payload); err != nil {
		logger.Error("bind request body", "error", err)
		return echo.ErrBadRequest
	}

	if err := c.Validate(payload); err != nil {
		logger.Error("invalid payload with validation errors")
		return err
	}

	if err := h.authService.RequestPasswordReset(c.Request().Context(), payload.Email); err != nil {
		logger.Error("forgot password", "error", err)

		if errors.Is(err, domain.ErrUserNotFound) {
			// To prevent user enumeration, we return 200 OK even if the user is not found.
			return c.NoContent(http.StatusOK)
		}

		return echo.ErrInternalServerError
	}

	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) ConfirmResetPassword(c echo.Context) error {
	logger := h.logger.With(
		slog.String("method", "ConfirmResetPassword"),
		slog.String("path", c.Request().URL.Path),
	)

	var payload model.ResetPasswordPayload
	if err := c.Bind(&payload); err != nil {
		logger.Error("bind request body", "error", err)
		return echo.ErrBadRequest
	}

	if err := c.Validate(payload); err != nil {
		logger.Error("invalid payload with validation errors")
		return err
	}

	session, err := h.authService.ResetPassword(c.Request().Context(), payload.Token, payload.NewPassword)
	if err != nil {
		logger.Error("reset password", "error", err)

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
	logger := h.logger.With(
		slog.String("method", "RequestChangeEmail"),
		slog.String("path", c.Request().URL.Path),
	)

	var payload model.RequestEmailChangePayload
	if err := c.Bind(&payload); err != nil {
		logger.Error("bind request body", "error", err)
		return echo.ErrBadRequest
	}

	if err := c.Validate(payload); err != nil {
		logger.Error("invalid payload with validation errors")
		return err
	}

	err := h.authService.RequestChangeEmail(c.Request().Context(), GetUserID(c), payload.NewEmail)
	if err != nil {
		logger.Error("request change email", "error", err)

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
	logger := h.logger.With(
		slog.String("method", "ConfirmChangeEmail"),
		slog.String("path", c.Request().URL.Path),
	)
	var payload model.ConfirmEmailChangePayload
	if err := c.Bind(&payload); err != nil {
		logger.Error("bind request body", "error", err)
		return echo.ErrBadRequest
	}

	if err := c.Validate(payload); err != nil {
		logger.Error("invalid payload with validation errors")
		return err
	}

	err := h.authService.ChangeEmail(c.Request().Context(), payload.Token)
	if err != nil {
		logger.Error("confirm change email", "error", err)

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
