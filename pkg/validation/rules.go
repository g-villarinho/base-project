package validation

import (
	"regexp"

	"github.com/go-playground/validator/v10"
)

const (
	passwordLenght = 8
)

func registerCustomRules(v *validator.Validate) error {
	if err := v.RegisterValidation("strong_password", validateStrongPassword); err != nil {
		return err
	}

	if err := v.RegisterValidation("br_phone", validateBrazilianPhone); err != nil {
		return err
	}

	return nil
}

// validateStrongPassword valida se a senha é forte
// Deve ter: maiúscula, minúscula, número e mínimo 8 caracteres
func validateStrongPassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	if len(password) < passwordLenght {
		return false
	}

	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)

	return hasUpper && hasLower && hasNumber
}

// validateBrazilianPhone valida telefones brasileiros
// Formatos aceitos: (11) 99999-9999, 11999999999, +5511999999999
func validateBrazilianPhone(fl validator.FieldLevel) bool {
	phone := fl.Field().String()

	phoneClean := regexp.MustCompile(`[^\d]`).ReplaceAllString(phone, "")

	patterns := []string{
		`^55\d{10,11}$`,
		`^\d{10,11}$`,
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, phoneClean); matched {
			return true
		}
	}

	return false
}
