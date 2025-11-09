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
func NotFound(c echo.Context, code, message string) error {
	problem := np.NewProblem(
		"https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Reference/Status/404",
		message,
		http.StatusNotFound,
		withCode(code),
		np.WithInstance(c.Request().URL.Path),
	)

	c.Response().Header().Set("Content-Type", np.ContentTypeProblemJSON)
	c.Response().WriteHeader(problem.Status)
	return c.JSON(problem.Status, problem)
}

// BadRequest returns a 400 Bad Request error response with details from the provided error.
func BadRequest(c echo.Context, code, message string) error {
	problem := np.NewProblem(
		"https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Reference/Status/400",
		"Bad Request",
		http.StatusBadRequest,
		np.WithDetail(message),
		withCode(code),
		np.WithInstance(c.Request().URL.Path),
	)

	c.Response().Header().Set("Content-Type", np.ContentTypeProblemJSON)
	c.Response().WriteHeader(problem.Status)
	return c.JSON(problem.Status, problem)
}

// Unauthorized returns a 401 Unauthorized error response with the provided message.
func Unauthorized(c echo.Context, code, message string) error {
	problem := np.NewProblem(
		"https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Reference/Status/401",
		"Unauthorized",
		http.StatusUnauthorized,
		np.WithDetail(message),
		withCode(code),
		np.WithInstance(c.Request().URL.Path),
	)

	c.Response().Header().Set("Content-Type", np.ContentTypeProblemJSON)
	c.Response().WriteHeader(problem.Status)
	return c.JSON(problem.Status, problem)
}

// ConflictError returns a 409 Conflict error response with the provided message.
func ConflictError(c echo.Context, code, message string) error {
	problem := np.NewProblem(
		"https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Reference/Status/409",
		"Conflict",
		http.StatusConflict,
		withCode(code),
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

	return BadRequest(c, "VALIDATION_ERROR", err.Error())
}

func Forbidden(c echo.Context, code, message string) error {
	problem := np.NewProblem(
		"https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Reference/Status/403",
		"Forbidden",
		http.StatusForbidden,
		withCode(code),
		np.WithDetail(message),
		np.WithInstance(c.Request().URL.Path),
	)

	c.Response().Header().Set("Content-Type", np.ContentTypeProblemJSON)
	c.Response().WriteHeader(problem.Status)
	return c.JSON(problem.Status, problem)
}

func InvalidBind(c echo.Context) error {
	problem := np.NewProblem(
		"https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Reference/Status/400",
		"Invalid Bind",
		http.StatusBadRequest,
		np.WithDetail("Invalid request payload. please check the submitted data."),
		np.WithInstance(c.Request().URL.Path),
	)

	c.Response().Header().Set("Content-Type", np.ContentTypeProblemJSON)
	c.Response().WriteHeader(problem.Status)
	return c.JSON(problem.Status, problem)
}

func withCode(code string) np.Option {
	return np.WithExtra("code", code)
}
