package validation

import (
	"errors"
	"log"
	"strings"

	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	en_translations "github.com/go-playground/validator/v10/translations/en"
)

var (
	validate *validator.Validate
	uni      *ut.UniversalTranslator
)

func init() {
	validate = validator.New()

	if err := registerCustomRules(validate); err != nil {
		log.Fatal(err)
	}

	enLocale := en.New()
	uni = ut.New(enLocale, enLocale)

	transEN, _ := uni.GetTranslator("en")

	if err := en_translations.RegisterDefaultTranslations(validate, transEN); err != nil {
		log.Fatal(err)
	}
}

type CustomValidator struct {
	validator *validator.Validate
}

func NewValidator() *CustomValidator {
	return &CustomValidator{
		validator: validate,
	}
}

func (cv *CustomValidator) Validate(i any) error {
	return cv.validator.Struct(i)
}

func FormatValidationErrors(err error, lang string) map[string]string {
	fields := make(map[string]string)

	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		trans, _ := uni.GetTranslator(lang)
		for _, fe := range validationErrors {
			fields[strings.ToLower(fe.Field())] = fe.Translate(trans)
		}
	}

	return fields
}
