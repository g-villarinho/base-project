package handler

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/g-villarinho/base-project/internal/api/echoctx"
	"github.com/g-villarinho/base-project/internal/api/model"
	"github.com/g-villarinho/base-project/internal/domain"
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

// RegisterAccount godoc
// @Summary      Register a new user account
// @Description  Creates a new user account and sends a verification email
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        payload  body      model.RegisterAccountPayload  true  "Registration details"
// @Success      201  "Account created successfully, verification email sent"
// @Failure      400  {object}  model.ProblemJSON  "Invalid request payload"
// @Failure      409  {object}  model.ProblemJSON  "Email already exists"
// @Failure      422  {object}  model.ProblemJSON  "Validation error"
// @Failure      500  {object}  model.ProblemJSON  "Internal server error"
// @Router       /auth/register [post]
func (h *AuthHandler) RegisterAccount(c echo.Context) error {
	logger := h.logger.With(
		slog.String("method", "RegisterAccount"),
	)

	var payload model.RegisterAccountPayload
	if err := c.Bind(&payload); err != nil {
		logger.Warn("bind payload", slog.Any("error", err))
		return InvalidBind(c)
	}

	if err := c.Validate(payload); err != nil {
		logger.Info("Payload validation failed")
		return ValidationError(c, err)
	}

	err := h.authService.RegisterAccount(c.Request().Context(), payload.Name, payload.Email, payload.Password)
	if err != nil {
		if errors.Is(err, domain.ErrEmailAlreadyExists) {
			logger.Warn("Registration conflict: email already exists")
			return ConflictError(c, "EMAIL_NOT_AVAILABLE", "The email address provided is not available")
		}

		logger.Error(
			"Failed to register account due to internal error",
			slog.Any("error", err),
		)

		return InternalServerError(c, "Failed to register account")
	}

	return c.NoContent(http.StatusCreated)
}

// VerifyEmail godoc
// @Summary      Verify email address
// @Description  Verifies user email using token from verification email
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        token  query     string  true  "Verification token from email"
// @Success      200  "Email verified successfully, session cookie set"
// @Failure      400  {object}  model.ProblemJSON  "Invalid or expired token"
// @Failure      422  {object}  model.ProblemJSON  "Validation error"
// @Failure      500  {object}  model.ProblemJSON  "Internal server error"
// @Router       /auth/verify-email [get]
func (h *AuthHandler) VerifyEmail(c echo.Context) error {
	logger := h.logger.With(
		slog.String("method", "VerifyEmail"),
	)

	var payload model.VerifyEmailPayload

	if err := c.Bind(&payload); err != nil {
		logger.Warn("bind payload", slog.Any("error", err))
		return InvalidBind(c)
	}

	if err := c.Validate(payload); err != nil {
		logger.Info("payload validation failed")
		return ValidationError(c, err)
	}

	clientInfo := echoctx.GetClientInfo(c)

	session, err := h.authService.VerifyEmail(c.Request().Context(), payload.Token, clientInfo.IPAddress, clientInfo.DeviceName, clientInfo.UserAgent)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidVerification) || errors.Is(err, domain.ErrVerificationNotFound) {
			logger.Warn("invalid verification", slog.Any("error", err))
			return BadRequest(c, "INVALID_TOKEN", "The verification token is invalid or has expired")
		}

		logger.Error("failed to verify email",
			slog.Any("error", err))

		return InternalServerError(c, "Failed to verify email")
	}

	h.cookieHandler.Set(c, session.Token, session.ExpiresAt)
	return c.NoContent(http.StatusOK)
}

// Login godoc
// @Summary      User login
// @Description  Authenticates user and creates a new session
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        payload  body      model.LoginPayload  true  "Login credentials"
// @Success      200  "Login successful, session cookie set"
// @Failure      401  {object}  model.ProblemJSON  "Invalid credentials"
// @Failure      403  {object}  model.ProblemJSON  "User account blocked"
// @Failure      409  {object}  model.ProblemJSON  "Email not verified"
// @Failure      422  {object}  model.ProblemJSON  "Validation error"
// @Failure      500  {object}  model.ProblemJSON  "Internal server error"
// @Router       /auth/login [post]
func (h *AuthHandler) Login(c echo.Context) error {
	logger := h.logger.With(
		slog.String("method", "Login"),
	)

	var payload model.LoginPayload
	if err := c.Bind(&payload); err != nil {
		logger.Warn("bind payload", slog.Any("error", err))
		return InvalidBind(c)
	}

	if err := c.Validate(payload); err != nil {
		logger.Info("payload validation failed")
		return ValidationError(c, err)
	}

	clientInfo := echoctx.GetClientInfo(c)

	session, err := h.authService.Login(c.Request().Context(), payload.Email, payload.Password, clientInfo.IPAddress, clientInfo.UserAgent, clientInfo.DeviceName)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) {
			logger.Warn("invalid credentials", slog.Any("error", err))
			return Unauthorized(c, "INVALID_CREDENTIALS", "Invalid email or password. Please try again.")
		}

		if errors.Is(err, domain.ErrUserBlocked) {
			logger.Warn("user account is blocked", slog.Any("error", err))
			return Forbidden(c, "USER_BLOCKED", "User account is blocked")
		}

		if errors.Is(err, domain.ErrEmailNotVerified) {
			logger.Warn("email address is not verified", slog.Any("error", err))
			return ConflictError(c, "EMAIL_NOT_VERIFIED", "Email address is not verified.")
		}

		logger.Error("failed to login",
			slog.Any("error", err))

		return InternalServerError(c, "Failed to login")
	}

	h.cookieHandler.Set(c, session.Token, session.ExpiresAt)
	return c.NoContent(http.StatusOK)
}

// Logout godoc
// @Summary      Logout current session
// @Description  Revokes the current session and clears the session cookie
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Success      200  "Logout successful"
// @Failure      401  {object}  model.ProblemJSON  "Unauthorized - authentication required"
// @Failure      500  {object}  model.ProblemJSON  "Internal server error"
// @Router       /auth/logout [delete]
func (h *AuthHandler) Logout(c echo.Context) error {
	logger := h.logger.With(
		slog.String("method", "Logout"),
		slog.String("user_id", echoctx.GetUserID(c).String()),
		slog.String("session_id", echoctx.GetSessionID(c).String()),
	)

	err := h.authService.Logout(c.Request().Context(), echoctx.GetUserID(c), echoctx.GetSessionID(c))
	if err != nil {
		logger.Error("failed to logout",
			slog.Any("error", err))
		return InternalServerError(c, "Failed to logout")
	}

	h.cookieHandler.Delete(c)
	return c.NoContent(http.StatusOK)
}

// UpdatePassword godoc
// @Summary      Update user password
// @Description  Changes the authenticated user's password
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Param        payload  body      model.UpdatePasswordPayload  true  "Password update details"
// @Success      200  "Password updated successfully"
// @Failure      400  {object}  model.ProblemJSON  "Current password incorrect"
// @Failure      401  {object}  model.ProblemJSON  "Unauthorized - authentication required"
// @Failure      422  {object}  model.ProblemJSON  "Validation error"
// @Failure      500  {object}  model.ProblemJSON  "Internal server error"
// @Router       /auth/password [patch]
func (h *AuthHandler) UpdatePassword(c echo.Context) error {
	logger := h.logger.With(
		slog.String("method", "UpdatePassword"),
		slog.String("user_id", echoctx.GetUserID(c).String()),
	)

	var payload model.UpdatePasswordPayload
	if err := c.Bind(&payload); err != nil {
		logger.Warn("bind payload", slog.Any("error", err))
		return InvalidBind(c)
	}

	if err := c.Validate(payload); err != nil {
		logger.Info("payload validation failed")
		return ValidationError(c, err)
	}

	err := h.authService.UpdatePassword(c.Request().Context(), echoctx.GetUserID(c), payload.CurrentPassword, payload.NewPassword)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			logger.Error("authenticated user not found in database",
				slog.Any("error", err))
			return InternalServerError(c, "An unexpected error occurred. Please try again.")
		}

		if errors.Is(err, domain.ErrPasswordMismatch) {
			logger.Warn("password mismatch", slog.Any("error", err))
			return BadRequest(c, "PASSWORD_MISMATCH", "Current password provided is incorrect.")
		}

		logger.Error("failed to update password",
			slog.Any("error", err))

		return InternalServerError(c, "Failed to update password")
	}

	return c.NoContent(http.StatusOK)
}

// ForgotPassword godoc
// @Summary      Request password reset
// @Description  Sends a password reset email to the user's registered email address
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        payload  body      model.ForgotPasswordPayload  true  "Email address"
// @Success      200  "Password reset email sent (or email not found - no enumeration)"
// @Failure      422  {object}  model.ProblemJSON  "Validation error"
// @Failure      500  {object}  model.ProblemJSON  "Internal server error"
// @Router       /auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(c echo.Context) error {
	logger := h.logger.With(
		slog.String("method", "ForgotPassword"),
	)

	var payload model.ForgotPasswordPayload
	if err := c.Bind(&payload); err != nil {
		logger.Warn("bind payload", slog.Any("error", err))
		return InvalidBind(c)
	}

	if err := c.Validate(payload); err != nil {
		logger.Info("payload validation failed")
		return ValidationError(c, err)
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

// ResetPassword godoc
// @Summary      Reset password with token
// @Description  Resets user password using token from reset email and creates new session
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        payload  body      model.ResetPasswordPayload  true  "Reset token and new password"
// @Success      200  "Password reset successful, session cookie set"
// @Failure      400  {object}  model.ProblemJSON  "Invalid or expired token"
// @Failure      422  {object}  model.ProblemJSON  "Validation error"
// @Failure      500  {object}  model.ProblemJSON  "Internal server error"
// @Router       /auth/reset-password [post]
func (h *AuthHandler) ResetPassword(c echo.Context) error {
	logger := h.logger.With(
		slog.String("method", "ConfirmResetPassword"),
	)

	var payload model.ResetPasswordPayload

	if err := c.Bind(&payload); err != nil {
		logger.Warn("bind payload", slog.Any("error", err))
		return InvalidBind(c)
	}

	if err := c.Validate(payload); err != nil {
		logger.Info("payload validation failed")
		return ValidationError(c, err)
	}

	session, err := h.authService.ResetPassword(c.Request().Context(), payload.Token, payload.NewPassword)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidVerification) || errors.Is(err, domain.ErrVerificationNotFound) {
			logger.Warn("invalid verification", slog.Any("error", err))
			return BadRequest(c, "INVALID_TOKEN", "The verification token is invalid or has expired")
		}

		logger.Error("failed to reset password",
			slog.Any("error", err))

		return InternalServerError(c, "Failed to reset password")
	}

	h.cookieHandler.Set(c, session.Token, session.ExpiresAt)
	return c.NoContent(http.StatusOK)
}

// RequestChangeEmail godoc
// @Summary      Request email change
// @Description  Initiates email change process by sending verification to new email
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Param        payload  body      model.RequestEmailChangePayload  true  "New email address"
// @Success      200  "Email change verification sent"
// @Failure      400  {object}  model.ProblemJSON  "New email same as current"
// @Failure      401  {object}  model.ProblemJSON  "Unauthorized - authentication required"
// @Failure      409  {object}  model.ProblemJSON  "Email already in use"
// @Failure      422  {object}  model.ProblemJSON  "Validation error"
// @Failure      500  {object}  model.ProblemJSON  "Internal server error"
// @Router       /auth/change-email [post]
func (h *AuthHandler) RequestChangeEmail(c echo.Context) error {
	logger := h.logger.With(
		slog.String("method", "RequestChangeEmail"),
		slog.String("user_id", echoctx.GetUserID(c).String()),
	)

	var payload model.RequestEmailChangePayload
	if err := c.Bind(&payload); err != nil {
		logger.Warn("bind payload", slog.Any("error", err))
		return InvalidBind(c)
	}

	if err := c.Validate(payload); err != nil {
		logger.Info("payload validation failed")
		return ValidationError(c, err)
	}

	err := h.authService.RequestChangeEmail(c.Request().Context(), echoctx.GetUserID(c), payload.NewEmail)
	if err != nil {
		if errors.Is(err, domain.ErrEmailInUse) {
			logger.Warn("email in use", slog.Any("error", err))
			return ConflictError(c, "EMAIL_IN_USE", "The email address is already in use.")
		}

		if errors.Is(err, domain.ErrUserNotFound) {
			logger.Error("authenticated user not found in database",
				slog.Any("error", err))
			return InternalServerError(c, "An unexpected error occurred. Please try again.")
		}

		if errors.Is(err, domain.ErrEmailIsTheSame) {
			logger.Warn("email is the same", slog.Any("error", err))
			return BadRequest(c, "EMAIL_IS_SAME", "The new email address must be different from the current email address.")
		}

		logger.Error("failed to request email change",
			slog.Any("error", err))

		return InternalServerError(c, "An unexpected error occurred while trying to request email change. Please try again.")
	}

	return c.NoContent(http.StatusOK)
}

// ConfirmChangeEmail godoc
// @Summary      Confirm email change
// @Description  Confirms email change using token from verification email
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        payload  body      model.ConfirmEmailChangePayload  true  "Verification token"
// @Success      200  "Email changed successfully"
// @Failure      400  {object}  model.ProblemJSON  "Invalid or expired token"
// @Failure      422  {object}  model.ProblemJSON  "Validation error"
// @Failure      500  {object}  model.ProblemJSON  "Internal server error"
// @Router       /auth/change-email/confirm [post]
func (h *AuthHandler) ConfirmChangeEmail(c echo.Context) error {
	logger := h.logger.With(
		slog.String("method", "ConfirmChangeEmail"),
	)

	var payload model.ConfirmEmailChangePayload

	if err := c.Bind(&payload); err != nil {
		logger.Warn("bind payload", slog.Any("error", err))
		return InvalidBind(c)
	}

	if err := c.Validate(payload); err != nil {
		logger.Info("payload validation failed")
		return ValidationError(c, err)
	}

	err := h.authService.ChangeEmail(c.Request().Context(), payload.Token)
	if err != nil {
		if errors.Is(err, domain.ErrVerificationNotFound) || errors.Is(err, domain.ErrInvalidVerification) {
			logger.Warn("invalid verification", slog.Any("error", err))
			return BadRequest(c, "INVALID_TOKEN", "The verification token is invalid or has expired.")
		}

		if errors.Is(err, domain.ErrUserNotFound) {
			logger.Error("authenticated user not found in database",
				slog.Any("error", err))
			return InternalServerError(c, "An unexpected error occurred. Please try again.")
		}

		logger.Error("failed to change email",
			slog.Any("error", err))

		return InternalServerError(c, "An unexpected error occurred while trying to change email. Please try again.")
	}

	return c.NoContent(http.StatusOK)
}
