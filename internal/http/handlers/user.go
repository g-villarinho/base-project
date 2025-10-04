package handlers

import (
	"errors"
	"net/http"

	"github.com/g-villarinho/base-project/internal/domain"
	httputil "github.com/g-villarinho/base-project/internal/http"
	"github.com/g-villarinho/base-project/internal/model"
	"github.com/g-villarinho/base-project/internal/service"
	"github.com/labstack/echo/v4"
)

type UserHandler struct {
	userService service.UserService
}

func NewUserHandler(userService service.UserService) *UserHandler {
	return &UserHandler{
		userService: userService,
	}
}

func (h *UserHandler) UpdateProfile(c echo.Context) error {
	var payload model.UpdateProfilePayload
	if err := c.Bind(&payload); err != nil {
		return echo.ErrBadRequest
	}

	if err := c.Validate(payload); err != nil {
		return err
	}

	if err := h.userService.UpdateUser(c.Request().Context(), httputil.GetUserID(c), payload.Name); err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}

		return echo.ErrInternalServerError
	}

	return c.NoContent(http.StatusOK)
}

func (h *UserHandler) GetProfile(c echo.Context) error {
	user, err := h.userService.GetUser(c.Request().Context(), httputil.GetUserID(c))
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}

		return echo.ErrInternalServerError
	}

	response := model.ProfileResponse{
		ID:    user.ID,
		Name:  user.Name,
		Email: user.Email,
	}

	return c.JSON(http.StatusOK, response)
}
