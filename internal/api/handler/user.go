package handler

import (
	"errors"
	"net/http"

	"github.com/g-villarinho/base-project/internal/api/echoctx"
	"github.com/g-villarinho/base-project/internal/api/model"
	"github.com/g-villarinho/base-project/internal/domain"
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

// UpdateProfile godoc
// @Summary      Update user profile
// @Description  Updates the authenticated user's profile information
// @Tags         User
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Param        payload  body      model.UpdateProfilePayload  true  "Profile update details"
// @Success      200  "Profile updated successfully"
// @Failure      401  {object}  model.ProblemJSON  "Unauthorized - authentication required"
// @Failure      404  {object}  model.ProblemJSON  "User not found"
// @Failure      422  {object}  model.ProblemJSON  "Validation error"
// @Failure      500  {object}  model.ProblemJSON  "Internal server error"
// @Router       /user/profile [patch]
func (h *UserHandler) UpdateProfile(c echo.Context) error {
	var payload model.UpdateProfilePayload
	if err := c.Bind(&payload); err != nil {
		return echo.ErrBadRequest
	}

	if err := c.Validate(payload); err != nil {
		return err
	}

	if err := h.userService.UpdateUser(c.Request().Context(), echoctx.GetUserID(c), payload.Name); err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}

		return echo.ErrInternalServerError
	}

	return c.NoContent(http.StatusOK)
}

// GetProfile godoc
// @Summary      Get user profile
// @Description  Retrieves the authenticated user's profile information
// @Tags         User
// @Accept       json
// @Produce      json
// @Security     CookieAuth
// @Success      200  {object}  model.ProfileResponse  "Profile retrieved successfully"
// @Failure      401  {object}  model.ProblemJSON  "Unauthorized - authentication required"
// @Failure      404  {object}  model.ProblemJSON  "User not found"
// @Failure      500  {object}  model.ProblemJSON  "Internal server error"
// @Router       /user/profile [get]
func (h *UserHandler) GetProfile(c echo.Context) error {
	user, err := h.userService.GetUser(c.Request().Context(), echoctx.GetUserID(c))
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
