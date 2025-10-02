package handler

import (
	"errors"
	"net/http"

	"github.com/g-villarinho/base-project/pkg/validation"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
)

func HttpErrorHandler(err error, ectx echo.Context) {
	if ectx.Response().Committed {
		return
	}

	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		lang := "en"
		details := validation.FormatValidationErrors(err, lang)
		response := map[string]any{"message": "Validation failed", "errors": details}
		ectx.JSON(http.StatusUnprocessableEntity, response)
		return
	}

	var httpError *echo.HTTPError
	if errors.As(err, &httpError) {
		ectx.JSON(httpError.Code, map[string]any{"message": httpError.Message})
		return
	}

	response := map[string]string{"message": "An unexpected error occurred"}
	ectx.JSON(http.StatusInternalServerError, response)
}
