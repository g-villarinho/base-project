package handler

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/g-villarinho/base-project/internal/model"
	"github.com/g-villarinho/base-project/internal/server/echoctx"
	"github.com/g-villarinho/base-project/internal/service"
	"github.com/labstack/echo/v4"
)

type AuthHandler struct {
	authService   service.AuthService
	cookieHandler CookieHandler
	logger        *slog.Logger
}

func NewAuthHandler(
	authService service.AuthService,
	cookieHandler CookieHandler,
	logger *slog.Logger,
) *AuthHandler {
	return &AuthHandler{
		authService:   authService,
		cookieHandler: cookieHandler,
		logger:        logger.With(slog.String("handler", "auth")),
	}
}

func (h *AuthHandler) RegisterAccount(c echo.Context) error {
	logger := h.logger.With(
		slog.String("method", "RegisterAccount"),
		slog.String("path", c.Path()),
	)

	var payload model.RegisterAccountPayload
	if err := c.Bind(&payload); err != nil {
		logger.Warn("Failed to bind payload", slog.Any("error", err))
		return BadRequest(c, err)
	}

	if err := c.Validate(payload); err != nil {
		logger.Info("Payload validation failed")
		return HandleValidationError(c, payload, err)
	}

	err := h.authService.RegisterAccount(c.Request().Context(), payload.Name, payload.Email, payload.Password)
	if err != nil {
		if errors.Is(err, domain.ErrEmailAlreadyExists) {
			logger.Warn("Registration conflict: email already exists")
			return ConflictError(c, "The email address provided is not available")
		}

		logger.Error(
			"Failed to register account due to internal error",
			slog.Any("error", err),
		)

		return InternalServerError(c, "Failed to register account")
	}

	return c.NoContent(http.StatusCreated)
}

func (h *AuthHandler) VerifyEmail(c echo.Context) error {
	var payload model.VerifyEmailPayload

	// Bind query params
	if err := echo.QueryParamsBinder(c).String("token", &payload.Token).BindError(); err != nil {
		return BadRequest(c, err)
	}

	if err := c.Validate(payload); err != nil {
		return HandleValidationError(c, payload, err)
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
			return NotFound(c, "Verification token not found")
		}

		if errors.Is(err, domain.ErrInvalidVerification) {
			return BadRequest(c, err)
		}

		return InternalServerError(c, "Failed to verify email")
	}

	h.cookieHandler.Set(c, session.Token, session.ExpiresAt)
	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) Login(c echo.Context) error {
	var payload model.LoginPayload
	if err := c.Bind(&payload); err != nil {
		return BadRequest(c, err)
	}

	if err := c.Validate(payload); err != nil {
		return HandleValidationError(c, payload, err)
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
			return Unauthorized(c, err.Error())
		}

		if errors.Is(err, domain.ErrUserBlocked) {
			return ConflictError(c, err.Error())
		}

		if errors.Is(err, domain.ErrEmailNotVerified) {
			return ConflictError(c, err.Error())
		}

		return InternalServerError(c, "Failed to login")
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
		return BadRequest(c, err)
	}

	if err := c.Validate(payload); err != nil {
		return HandleValidationError(c, payload, err)
	}

	err := h.authService.UpdatePassword(c.Request().Context(), echoctx.GetUserID(c), payload.CurrentPassword, payload.NewPassword)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return NotFound(c, err.Error())
		}

		if errors.Is(err, domain.ErrPasswordMismatch) {
			return Unauthorized(c, err.Error())
		}

		return InternalServerError(c, "Failed to update password")
	}

	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) RequestResetPassword(c echo.Context) error {
	var payload model.ForgotPasswordPayload
	if err := c.Bind(&payload); err != nil {
		return BadRequest(c, err)
	}

	if err := c.Validate(payload); err != nil {
		return HandleValidationError(c, payload, err)
	}

	if err := h.authService.RequestPasswordReset(c.Request().Context(), payload.Email); err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			// To prevent user enumeration, we return 200 OK even if the user is not found.
			return c.NoContent(http.StatusOK)
		}

		return InternalServerError(c, "Failed to request password reset")
	}

	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) ConfirmResetPassword(c echo.Context) error {
	var payload model.ResetPasswordPayload

	if err := echo.QueryParamsBinder(c).String("token", &payload.Token).BindError(); err != nil {
		return BadRequest(c, err)
	}

	if err := c.Bind(&payload); err != nil {
		return BadRequest(c, err)
	}

	if err := c.Validate(payload); err != nil {
		return HandleValidationError(c, payload, err)
	}

	session, err := h.authService.ResetPassword(c.Request().Context(), payload.Token, payload.NewPassword)
	if err != nil {
		if errors.Is(err, domain.ErrVerificationNotFound) {
			return NotFound(c, "Verification token not found")
		}

		if errors.Is(err, domain.ErrInvalidVerification) {
			return BadRequest(c, err)
		}

		return InternalServerError(c, "Failed to reset password")
	}

	h.cookieHandler.Set(c, session.Token, session.ExpiresAt)
	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) RequestChangeEmail(c echo.Context) error {
	var payload model.RequestEmailChangePayload
	if err := c.Bind(&payload); err != nil {
		return BadRequest(c, err)
	}

	if err := c.Validate(payload); err != nil {
		return HandleValidationError(c, payload, err)
	}

	err := h.authService.RequestChangeEmail(c.Request().Context(), echoctx.GetUserID(c), payload.NewEmail)
	if err != nil {
		if errors.Is(err, domain.ErrEmailInUse) {
			return ConflictError(c, err.Error())
		}

		if errors.Is(err, domain.ErrUserNotFound) {
			return NotFound(c, err.Error())
		}

		if errors.Is(err, domain.ErrEmailIsTheSame) {
			return BadRequest(c, err)
		}

		return InternalServerError(c, "Failed to request email change")
	}

	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) ConfirmChangeEmail(c echo.Context) error {
	var payload model.ConfirmEmailChangePayload

	if err := echo.QueryParamsBinder(c).String("token", &payload.Token).BindError(); err != nil {
		return BadRequest(c, err)
	}

	if err := c.Validate(payload); err != nil {
		return HandleValidationError(c, payload, err)
	}

	err := h.authService.ChangeEmail(c.Request().Context(), payload.Token)
	if err != nil {
		if errors.Is(err, domain.ErrVerificationNotFound) {
			return NotFound(c, "Verification token not found")
		}

		if errors.Is(err, domain.ErrInvalidVerification) {
			return BadRequest(c, err)
		}

		if errors.Is(err, domain.ErrUserNotFound) {
			return NotFound(c, err.Error())
		}

		return InternalServerError(c, "Failed to change email")
	}

	return c.NoContent(http.StatusOK)
}
