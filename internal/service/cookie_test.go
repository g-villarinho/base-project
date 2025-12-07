package service

import (
	"context"
	"testing"

	"github.com/g-villarinho/base-project/config"
	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupCookieService(t *testing.T) CookieService {
	t.Helper()

	cfg := &config.Config{
		Session: config.Session{
			Secret: "test-secret-key-for-cookie-signing",
		},
	}

	service := NewCookieService(cfg)
	return service
}

func TestSign(t *testing.T) {
	t.Run("should successfully sign a value", func(t *testing.T) {
		// Arrange
		service := setupCookieService(t)
		ctx := context.Background()
		value := "session-token-123"

		// Act
		signedValue := service.Sign(ctx, value)

		// Assert
		assert.NotEmpty(t, signedValue)
		assert.Contains(t, signedValue, ".")
		assert.Contains(t, signedValue, value)
	})

	t.Run("should produce consistent signatures for the same value", func(t *testing.T) {
		// Arrange
		service := setupCookieService(t)
		ctx := context.Background()
		value := "test-value"

		// Act
		signedValue1 := service.Sign(ctx, value)
		signedValue2 := service.Sign(ctx, value)

		// Assert
		assert.Equal(t, signedValue1, signedValue2)
	})

	t.Run("should produce different signatures for different values", func(t *testing.T) {
		// Arrange
		service := setupCookieService(t)
		ctx := context.Background()
		value1 := "test-value-1"
		value2 := "test-value-2"

		// Act
		signedValue1 := service.Sign(ctx, value1)
		signedValue2 := service.Sign(ctx, value2)

		// Assert
		assert.NotEqual(t, signedValue1, signedValue2)
	})

	t.Run("should handle empty string value", func(t *testing.T) {
		// Arrange
		service := setupCookieService(t)
		ctx := context.Background()
		value := ""

		// Act
		signedValue := service.Sign(ctx, value)

		// Assert
		assert.NotEmpty(t, signedValue)
		assert.Contains(t, signedValue, ".")
	})
}

func TestVerify(t *testing.T) {
	t.Run("should successfully verify a valid signed value", func(t *testing.T) {
		// Arrange
		service := setupCookieService(t)
		ctx := context.Background()
		originalValue := "session-token-123"
		signedValue := service.Sign(ctx, originalValue)

		// Act
		verifiedValue, err := service.Verify(ctx, signedValue)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, originalValue, verifiedValue)
	})

	t.Run("should return error when signed value has invalid format with no dot", func(t *testing.T) {
		// Arrange
		service := setupCookieService(t)
		ctx := context.Background()
		invalidSignedValue := "invalid-value-without-dot"

		// Act
		verifiedValue, err := service.Verify(ctx, invalidSignedValue)

		// Assert
		require.Error(t, err)
		assert.Equal(t, domain.ErrInvalidSignature, err)
		assert.Empty(t, verifiedValue)
	})

	t.Run("should return error when signed value has more than two parts", func(t *testing.T) {
		// Arrange
		service := setupCookieService(t)
		ctx := context.Background()
		invalidSignedValue := "part1.part2.part3"

		// Act
		verifiedValue, err := service.Verify(ctx, invalidSignedValue)

		// Assert
		require.Error(t, err)
		assert.Equal(t, domain.ErrInvalidSignature, err)
		assert.Empty(t, verifiedValue)
	})

	t.Run("should return error when signature does not match", func(t *testing.T) {
		// Arrange
		service := setupCookieService(t)
		ctx := context.Background()
		value := "session-token-123"
		invalidSignedValue := value + ".invalidsignature"

		// Act
		verifiedValue, err := service.Verify(ctx, invalidSignedValue)

		// Assert
		require.Error(t, err)
		assert.Equal(t, domain.ErrInvalidSignature, err)
		assert.Empty(t, verifiedValue)
	})

	t.Run("should return error when value is tampered but signature remains", func(t *testing.T) {
		// Arrange
		service := setupCookieService(t)
		ctx := context.Background()
		originalValue := "session-token-123"
		signedValue := service.Sign(ctx, originalValue)

		// Extract signature and use it with different value
		parts := splitSignedValue(signedValue)
		tamperedValue := "tampered-value." + parts[1]

		// Act
		verifiedValue, err := service.Verify(ctx, tamperedValue)

		// Assert
		require.Error(t, err)
		assert.Equal(t, domain.ErrInvalidSignature, err)
		assert.Empty(t, verifiedValue)
	})

	t.Run("should verify empty string value when properly signed", func(t *testing.T) {
		// Arrange
		service := setupCookieService(t)
		ctx := context.Background()
		originalValue := ""
		signedValue := service.Sign(ctx, originalValue)

		// Act
		verifiedValue, err := service.Verify(ctx, signedValue)

		// Assert
		require.NoError(t, err)
		assert.Equal(t, originalValue, verifiedValue)
	})

	t.Run("should return error when signed with different secret", func(t *testing.T) {
		// Arrange
		service1 := setupCookieService(t)

		// Create service with different secret
		cfg2 := &config.Config{
			Session: config.Session{
				Secret: "different-secret-key",
			},
		}
		service2 := NewCookieService(cfg2)

		ctx := context.Background()
		originalValue := "session-token-123"
		signedValue := service1.Sign(ctx, originalValue)

		// Act - try to verify with service using different secret
		verifiedValue, err := service2.Verify(ctx, signedValue)

		// Assert
		require.Error(t, err)
		assert.Equal(t, domain.ErrInvalidSignature, err)
		assert.Empty(t, verifiedValue)
	})
}

// Helper function to split signed value for testing
func splitSignedValue(signedValue string) []string {
	parts := make([]string, 2)
	for i, part := range []byte(signedValue) {
		if part == '.' {
			parts[0] = signedValue[:i]
			parts[1] = signedValue[i+1:]
			break
		}
	}
	return parts
}
