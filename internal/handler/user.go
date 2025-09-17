package handler

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/g-villarinho/user-demo/internal/domain"
	"github.com/g-villarinho/user-demo/internal/model"
	"github.com/g-villarinho/user-demo/internal/service"
	"github.com/labstack/echo/v4"
)


type UserHandler struct {
	userService service.UserService
	logger *slog.Logger
}

func NewUserHandler(userService service.UserService, logger *slog.Logger) *UserHandler {
	return &UserHandler{
		userService: userService,
    logger:      logger.With(slog.String("handler", "user")),
	}	
}

func (h *UserHandler) UpdateProfile(c echo.Context) error {
	logger := h.logger.With(
		slog.String("method", "UpdateProfile"),
		slog.String("path", c.Request().URL.Path),
	)

	var payload model.UpdateProfilePayload
	if err := c.Bind(&payload); err != nil {
		logger.Error("bind request body", "error", err)
		return echo.ErrBadRequest
	}

	if err := c.Validate(payload); err != nil {
		logger.Error("invalid payload with validation errors")
		return err
	}

	if err := h.userService.UpdateProfile(c.Request().Context(), GetUserID(c), payload.Name); err != nil {
		logger.Error("update profile", "error", err)

		if errors.Is(err, domain.ErrUserNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}

		return echo.ErrInternalServerError
	}

	return c.NoContent(http.StatusOK)
}
