package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

var (
	ErrInvalidSignature = errors.New("invalid signature")
)

type Signer interface {
	Sign(value string) string
	Verify(signedValue string) (string, error)
}

type hmacSigner struct {
	secret []byte
}

func NewSigner(secret string) Signer {
	return &hmacSigner{
		secret: []byte(secret),
	}
}

func (s *hmacSigner) Sign(value string) string {
	return sign(value, s.secret)
}

func (s *hmacSigner) Verify(signedValue string) (string, error) {
	parts := strings.Split(signedValue, ".")
	if len(parts) != 2 {
		return "", ErrInvalidSignature
	}

	value, signature := parts[0], parts[1]

	expectedSignature := sign(value, s.secret)
	expectedParts := strings.Split(expectedSignature, ".")

	if len(expectedParts) == 2 && hmac.Equal([]byte(signature), []byte(expectedParts[1])) {
		return value, nil
	}

	return "", ErrInvalidSignature
}

func sign(value string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(value))
	signature := hex.EncodeToString(mac.Sum(nil))
	return value + "." + signature
}
