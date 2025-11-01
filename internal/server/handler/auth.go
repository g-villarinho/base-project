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
	)

	var payload model.RegisterAccountPayload
	if err := c.Bind(&payload); err != nil {
		logger.Warn("bind payload", slog.Any("error", err))
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
	logger := h.logger.With(
		slog.String("method", "VerifyEmail"),
	)

	var payload model.VerifyEmailPayload

	if err := c.Bind(&payload); err != nil {
		logger.Warn("bind payload", slog.Any("error", err))
		return BadRequest(c, err)
	}

	if err := c.Validate(payload); err != nil {
		logger.Info("payload validation failed")
		return HandleValidationError(c, payload, err)
	}

	clientInfo := echoctx.GetClientInfo(c)

	session, err := h.authService.VerifyEmail(c.Request().Context(), payload.Token, clientInfo.IPAddress, clientInfo.DeviceName, clientInfo.UserAgent)
	if err != nil {
		if errors.Is(err, domain.ErrVerificationNotFound) {
			logger.Warn("verification not found", slog.Any("error", err))
			return NotFound(c, "Verification token not found")
		}

		if errors.Is(err, domain.ErrInvalidVerification) {
			logger.Warn("invalid verification", slog.Any("error", err))
			return BadRequest(c, err)
		}

		logger.Error("failed to verify email",
			slog.Any("error", err))

		return InternalServerError(c, "Failed to verify email")
	}

	h.cookieHandler.Set(c, session.Token, session.ExpiresAt)
	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) Login(c echo.Context) error {
	logger := h.logger.With(
		slog.String("method", "Login"),
	)

	var payload model.LoginPayload
	if err := c.Bind(&payload); err != nil {
		logger.Warn("bind payload", slog.Any("error", err))
		return BadRequest(c, err)
	}

	if err := c.Validate(payload); err != nil {
		logger.Info("payload validation failed")
		return HandleValidationError(c, payload, err)
	}

	clientInfo := echoctx.GetClientInfo(c)

	session, err := h.authService.Login(c.Request().Context(), payload.Email, payload.Password, clientInfo.IPAddress, clientInfo.UserAgent, clientInfo.DeviceName)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) {
			logger.Warn("invalid credentials", slog.Any("error", err))
			return Unauthorized(c, "Invalid email or password. Please try again.")
		}

		if errors.Is(err, domain.ErrUserBlocked) {
			logger.Warn("user account is blocked", slog.Any("error", err))
			return Forbidden(c, "User account is blocked")
		}

		if errors.Is(err, domain.ErrEmailNotVerified) {
			logger.Warn("email address is not verified", slog.Any("error", err))
			return ConflictError(c, "Email address is not verified")
		}

		logger.Error("failed to login",
			slog.Any("error", err))

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
	logger := h.logger.With(
		slog.String("method", "UpdatePassword"),
		slog.String("user_id", echoctx.GetUserID(c).String()),
	)

	var payload model.UpdatePasswordPayload
	if err := c.Bind(&payload); err != nil {
		logger.Warn("bind payload", slog.Any("error", err))
		return BadRequest(c, err)
	}

	if err := c.Validate(payload); err != nil {
		logger.Info("payload validation failed")
		return HandleValidationError(c, payload, err)
	}

	err := h.authService.UpdatePassword(c.Request().Context(), echoctx.GetUserID(c), payload.CurrentPassword, payload.NewPassword)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			logger.Warn("user not found", slog.Any("error", err))
			return NotFound(c, "Cannot find user to perform password update")
		}

		if errors.Is(err, domain.ErrPasswordMismatch) {
			logger.Warn("password mismatch", slog.Any("error", err))
			return Unauthorized(c, "Current password is incorrect")
		}

		logger.Error("failed to update password",
			slog.Any("error", err))

		return InternalServerError(c, "Failed to update password")
	}

	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) RequestResetPassword(c echo.Context) error {
	logger := h.logger.With(
		slog.String("method", "RequestResetPassword"),
	)

	var payload model.ForgotPasswordPayload
	if err := c.Bind(&payload); err != nil {
		logger.Warn("bind payload", slog.Any("error", err))
		return BadRequest(c, err)
	}

	if err := c.Validate(payload); err != nil {
		logger.Info("payload validation failed")
		return HandleValidationError(c, payload, err)
	}

	if err := h.authService.RequestPasswordReset(c.Request().Context(), payload.Email); err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			logger.Warn("user not found", slog.Any("error", err))
			// To prevent user enumeration, we return 200 OK even if the user is not found.
			return c.NoContent(http.StatusOK)
		}

		logger.Error("failed to request password reset",
			slog.Any("error", err))

		return InternalServerError(c, "Failed to request password reset")
	}

	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) ConfirmResetPassword(c echo.Context) error {
	logger := h.logger.With(
		slog.String("method", "ConfirmResetPassword"),
	)

	var payload model.ResetPasswordPayload

	if err := c.Bind(&payload); err != nil {
		logger.Warn("bind payload", slog.Any("error", err))
		return BadRequest(c, err)
	}

	if err := c.Validate(payload); err != nil {
		logger.Info("payload validation failed")
		return HandleValidationError(c, payload, err)
	}

	session, err := h.authService.ResetPassword(c.Request().Context(), payload.Token, payload.NewPassword)
	if err != nil {
		if errors.Is(err, domain.ErrVerificationNotFound) {
			logger.Warn("verification not found", slog.Any("error", err))
			return NotFound(c, "Verification token not found")
		}

		if errors.Is(err, domain.ErrInvalidVerification) {
			logger.Warn("invalid verification", slog.Any("error", err))
			return BadRequest(c, err)
		}

		logger.Error("failed to reset password",
			slog.Any("error", err))

		return InternalServerError(c, "Failed to reset password")
	}

	h.cookieHandler.Set(c, session.Token, session.ExpiresAt)
	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) RequestChangeEmail(c echo.Context) error {
	logger := h.logger.With(
		slog.String("method", "RequestChangeEmail"),
		slog.String("user_id", echoctx.GetUserID(c).String()),
	)

	var payload model.RequestEmailChangePayload
	if err := c.Bind(&payload); err != nil {
		logger.Warn("bind payload", slog.Any("error", err))
		return BadRequest(c, err)
	}

	if err := c.Validate(payload); err != nil {
		logger.Info("payload validation failed")
		return HandleValidationError(c, payload, err)
	}

	err := h.authService.RequestChangeEmail(c.Request().Context(), echoctx.GetUserID(c), payload.NewEmail)
	if err != nil {
		if errors.Is(err, domain.ErrEmailInUse) {
			logger.Warn("email in use", slog.Any("error", err))
			return ConflictError(c, err.Error())
		}

		if errors.Is(err, domain.ErrUserNotFound) {
			logger.Warn("user not found", slog.Any("error", err))
			return NotFound(c, err.Error())
		}

		if errors.Is(err, domain.ErrEmailIsTheSame) {
			logger.Warn("email is the same", slog.Any("error", err))
			return BadRequest(c, err)
		}

		logger.Error("failed to request email change",
			slog.Any("error", err))

		return InternalServerError(c, "Failed to request email change")
	}

	return c.NoContent(http.StatusOK)
}

func (h *AuthHandler) ConfirmChangeEmail(c echo.Context) error {
	logger := h.logger.With(
		slog.String("method", "ConfirmChangeEmail"),
	)

	var payload model.ConfirmEmailChangePayload

	if err := c.Bind(&payload); err != nil {
		logger.Warn("bind payload", slog.Any("error", err))
		return BadRequest(c, err)
	}

	if err := c.Validate(payload); err != nil {
		logger.Info("payload validation failed")
		return HandleValidationError(c, payload, err)
	}

	err := h.authService.ChangeEmail(c.Request().Context(), payload.Token)
	if err != nil {
		if errors.Is(err, domain.ErrVerificationNotFound) {
			logger.Warn("verification not found", slog.Any("error", err))
			return NotFound(c, "Verification token not found")
		}

		if errors.Is(err, domain.ErrInvalidVerification) {
			logger.Warn("invalid verification", slog.Any("error", err))
			return BadRequest(c, err)
		}

		if errors.Is(err, domain.ErrUserNotFound) {
			logger.Warn("user not found", slog.Any("error", err))
			return NotFound(c, err.Error())
		}

		return InternalServerError(c, "Failed to change email")
	}

	return c.NoContent(http.StatusOK)
}
