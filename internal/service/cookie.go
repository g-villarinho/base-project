package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/g-villarinho/base-project/config"
	"github.com/g-villarinho/base-project/internal/domain"
)

type CookieService interface {
	Sign(ctx context.Context, value string) string
	Verify(ctx context.Context, signedValue string) (string, error)
}

type CookieServiceImpl struct {
	secret []byte
}

func NewCookieService(config *config.Config) CookieService {
	return &CookieServiceImpl{
		secret: []byte(config.Session.Secret),
	}
}

func (s CookieServiceImpl) Sign(ctx context.Context, value string) string {
	return s.sign(value)
}

func (s CookieServiceImpl) Verify(ctx context.Context, signedValue string) (string, error) {
	parts := strings.Split(signedValue, ".")
	if len(parts) != 2 {
		return "", domain.ErrInvalidSignature
	}

	value, signature := parts[0], parts[1]

	expectedSignature := s.sign(value)
	expectedParts := strings.Split(expectedSignature, ".")

	if len(expectedParts) == 2 && hmac.Equal([]byte(signature), []byte(expectedParts[1])) {
		return value, nil
	}

	return "", domain.ErrInvalidSignature
}

func (s CookieServiceImpl) sign(value string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(value))
	signature := hex.EncodeToString(mac.Sum(nil))
	return value + "." + signature
}
