package crypto

import (
	"crypto/rand"
	"encoding/hex"
)

func CreateRandomStringGenerator(size int) (string, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
