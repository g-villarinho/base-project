package handler

import (
	"errors"
	"net/http"

	"github.com/g-villarinho/base-project/pkg/validation"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	np "github.com/lucasvillarinho/noproblem"
)

// InternalServerError returns a 500 Internal Server Error response.
func InternalServerError(c echo.Context, title string) error {
	problem := np.NewProblem(
		"https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Reference/Status/500",
		title,
		http.StatusInternalServerError,
		np.WithInstance(c.Request().URL.Path),
	)

	c.Response().Header().Set("Content-Type", np.ContentTypeProblemJSON)
	c.Response().WriteHeader(problem.Status)
	return c.JSON(problem.Status, problem)
}

// NotFound returns a 404 Not Found error response with the provided message.
func NotFound(c echo.Context, message string) error {
	problem := np.NewProblem(
		"https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Reference/Status/404",
		message,
		http.StatusNotFound,
		np.WithInstance(c.Request().URL.Path),
	)

	c.Response().Header().Set("Content-Type", np.ContentTypeProblemJSON)
	c.Response().WriteHeader(problem.Status)
	return c.JSON(problem.Status, problem)
}

// BadRequest returns a 400 Bad Request error response with details from the provided error.
func BadRequest(c echo.Context, message string) error {
	problem := np.NewProblem(
		"https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Reference/Status/400",
		"Bad Request",
		http.StatusBadRequest,
		np.WithDetail(message),
		np.WithInstance(c.Request().URL.Path),
	)

	c.Response().Header().Set("Content-Type", np.ContentTypeProblemJSON)
	c.Response().WriteHeader(problem.Status)
	return c.JSON(problem.Status, problem)
}

// Unauthorized returns a 401 Unauthorized error response with the provided message.
func Unauthorized(c echo.Context, message string) error {
	problem := np.NewProblem(
		"https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Reference/Status/401",
		"Unauthorized",
		http.StatusUnauthorized,
		np.WithDetail(message),
		np.WithInstance(c.Request().URL.Path),
	)

	c.Response().Header().Set("Content-Type", np.ContentTypeProblemJSON)
	c.Response().WriteHeader(problem.Status)
	return c.JSON(problem.Status, problem)
}

// ConflictError returns a 409 Conflict error response with the provided message.
func ConflictError(c echo.Context, message string) error {
	problem := np.NewProblem(
		"https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Reference/Status/409",
		"Conflict",
		http.StatusConflict,
		np.WithDetail(message),
		np.WithInstance(c.Request().URL.Path),
	)

	c.Response().Header().Set("Content-Type", np.ContentTypeProblemJSON)
	c.Response().WriteHeader(problem.Status)
	return c.JSON(problem.Status, problem)
}

// ValidationError returns a 422 Unprocessable Entity error response with validation errors.
func ValidationError(c echo.Context, err error) error {
	var validationErrs validator.ValidationErrors
	if errors.As(err, &validationErrs) {
		lang := c.Request().Header.Get("Accept-Language")
		validationErrors := validation.FormatValidationErrors(err, lang)

		problem := np.NewProblem(
			"https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Reference/Status/422",
			"Your request is not valid.",
			http.StatusUnprocessableEntity,
			np.WithInstance(c.Request().URL.Path),
			np.WithExtra("errors", validationErrors),
		)

		c.Response().Header().Set("Content-Type", np.ContentTypeProblemJSON)
		c.Response().WriteHeader(problem.Status)
		return c.JSON(problem.Status, problem)
	}

	return BadRequest(c, err.Error())
}

func Forbidden(c echo.Context, message string) error {
	problem := np.NewProblem(
		"https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Reference/Status/403",
		"Forbidden",
		http.StatusForbidden,
		np.WithDetail(message),
		np.WithInstance(c.Request().URL.Path),
	)

	c.Response().Header().Set("Content-Type", np.ContentTypeProblemJSON)
	c.Response().WriteHeader(problem.Status)
	return c.JSON(problem.Status, problem)
}

// SetupRequired returns a 428 Precondition Required error response indicating application setup is needed.
func SetupRequired(c echo.Context) error {
	problem := np.NewProblem(
		"https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Reference/Status/428",
		"Setup Required",
		http.StatusPreconditionRequired,
		np.WithDetail("Application setup is required before accessing this resource"),
		np.WithInstance(c.Request().URL.Path),
	)

	c.Response().Header().Set("Content-Type", np.ContentTypeProblemJSON)
	c.Response().WriteHeader(problem.Status)
	return c.JSON(problem.Status, problem)
}
