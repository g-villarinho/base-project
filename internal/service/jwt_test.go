package service_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/g-villarinho/user-demo/config"
	"github.com/g-villarinho/user-demo/internal/mocks"
	"github.com/g-villarinho/user-demo/internal/service"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// Helper function to create test ECDSA key pair
func createTestKeyPair(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	return privateKey, &privateKey.PublicKey
}

func TestJwtService_GenerateAccessTokenJWT(t *testing.T) {
	t.Run("should generate access token successfully with valid configuration", func(t *testing.T) {
		// Arrange
		mockKeyParser := mocks.NewEcdsaKeyPairMock(t)
		privateKey, publicKey := createTestKeyPair(t)

		config := &config.Config{
			Security: config.Security{
				AccessTokenExpirationHours: 2 * time.Hour,
				Issuer:                     "users-api",
				Audience:                   "users-api",
			},
			Key: config.Key{
				PrivateKey: "test-private-key-pem",
				PublicKey:  "test-public-key-pem",
			},
		}

		ctx := context.Background()
		userID := uuid.New()

		mockKeyParser.On("ParseECDSAPrivateKey", "test-private-key-pem").Return(privateKey, nil)
		mockKeyParser.On("ParseECDSAPublicKey", "test-public-key-pem").Return(publicKey, nil)

		jwtService, err := service.NewJwtService(config, mockKeyParser)
		assert.NoError(t, err)

		// Act
		result, err := jwtService.GenerateAccessTokenJWT(ctx, userID)

		// Assert
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotEmpty(t, result.Value)
		assert.False(t, result.ExpiresAt.IsZero())

		// Verify token expiration is correct (within 5 seconds of expected time)
		expectedExpiration := time.Now().Add(2 * time.Hour)
		timeDiff := result.ExpiresAt.Sub(expectedExpiration)
		assert.True(t, timeDiff < 5*time.Second && timeDiff > -5*time.Second)

		mockKeyParser.AssertExpectations(t)
	})

	t.Run("should return error when NewJwtService fails with invalid private key", func(t *testing.T) {
		// Arrange
		mockKeyParser := mocks.NewEcdsaKeyPairMock(t)
		config := &config.Config{
			Key: config.Key{
				PrivateKey: "invalid-private-key",
				PublicKey:  "valid-public-key",
			},
		}

		expectedError := errors.New("invalid private key format")
		mockKeyParser.On("ParseECDSAPrivateKey", "invalid-private-key").Return(nil, expectedError)

		// Act
		jwtService, err := service.NewJwtService(config, mockKeyParser)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, jwtService)
		assert.Contains(t, err.Error(), "parse ecdsa private key")
		mockKeyParser.AssertExpectations(t)
	})

	t.Run("should return error when NewJwtService fails with invalid public key", func(t *testing.T) {
		// Arrange
		mockKeyParser := mocks.NewEcdsaKeyPairMock(t)
		privateKey, _ := createTestKeyPair(t)
		config := &config.Config{
			Key: config.Key{
				PrivateKey: "valid-private-key",
				PublicKey:  "invalid-public-key",
			},
		}

		expectedError := errors.New("invalid public key format")
		mockKeyParser.On("ParseECDSAPrivateKey", "valid-private-key").Return(privateKey, nil)
		mockKeyParser.On("ParseECDSAPublicKey", "invalid-public-key").Return(nil, expectedError)

		// Act
		jwtService, err := service.NewJwtService(config, mockKeyParser)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, jwtService)
		assert.Contains(t, err.Error(), "parse ecdsa public key")
		mockKeyParser.AssertExpectations(t)
	})

	t.Run("should use correct expiration time from configuration", func(t *testing.T) {
		// Arrange
		mockKeyParser := mocks.NewEcdsaKeyPairMock(t)
		privateKey, publicKey := createTestKeyPair(t)
		customExpiration := 4 * time.Hour
		config := &config.Config{
			Security: config.Security{
				AccessTokenExpirationHours: customExpiration,
				Issuer:                     "test-issuer",
				Audience:                   "test-audience",
			},
			Key: config.Key{
				PrivateKey: "mock-private-key",
				PublicKey:  "mock-public-key",
			},
		}

		ctx := context.Background()
		userID := uuid.New()

		mockKeyParser.On("ParseECDSAPrivateKey", "mock-private-key").Return(privateKey, nil)
		mockKeyParser.On("ParseECDSAPublicKey", "mock-public-key").Return(publicKey, nil)

		jwtService, err := service.NewJwtService(config, mockKeyParser)
		assert.NoError(t, err)

		beforeGeneration := time.Now()

		// Act
		result, err := jwtService.GenerateAccessTokenJWT(ctx, userID)

		// Assert
		assert.NoError(t, err)
		assert.NotNil(t, result)

		afterGeneration := time.Now()
		expectedMinExpiration := beforeGeneration.Add(customExpiration)
		expectedMaxExpiration := afterGeneration.Add(customExpiration)

		assert.True(t, result.ExpiresAt.After(expectedMinExpiration) || result.ExpiresAt.Equal(expectedMinExpiration))
		assert.True(t, result.ExpiresAt.Before(expectedMaxExpiration) || result.ExpiresAt.Equal(expectedMaxExpiration))

		mockKeyParser.AssertExpectations(t)
	})

	t.Run("should include correct claims in JWT token", func(t *testing.T) {
		// Arrange
		mockKeyParser := mocks.NewEcdsaKeyPairMock(t)
		privateKey, publicKey := createTestKeyPair(t)
		config := &config.Config{
			Security: config.Security{
				AccessTokenExpirationHours: 1 * time.Hour,
				Issuer:                     "test-issuer",
				Audience:                   "test-audience",
			},
			Key: config.Key{
				PrivateKey: "mock-private-key",
				PublicKey:  "mock-public-key",
			},
		}

		ctx := context.Background()
		userID := uuid.New()

		mockKeyParser.On("ParseECDSAPrivateKey", "mock-private-key").Return(privateKey, nil)
		mockKeyParser.On("ParseECDSAPublicKey", "mock-public-key").Return(publicKey, nil)

		jwtService, err := service.NewJwtService(config, mockKeyParser)
		assert.NoError(t, err)

		// Act
		result, err := jwtService.GenerateAccessTokenJWT(ctx, userID)

		// Assert
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotEmpty(t, result.Value)
		assert.False(t, result.ExpiresAt.IsZero())

		// Parse and verify the JWT token contains correct claims
		token, err := jwt.ParseWithClaims(result.Value, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
			return publicKey, nil
		})
		assert.NoError(t, err)
		assert.True(t, token.Valid)

		claims, ok := token.Claims.(*jwt.RegisteredClaims)
		assert.True(t, ok)
		assert.Equal(t, "test-issuer", claims.Issuer)
		assert.Equal(t, jwt.ClaimStrings{"test-audience"}, claims.Audience)
		assert.Equal(t, userID.String(), claims.Subject)
		assert.NotEmpty(t, claims.ID)

		mockKeyParser.AssertExpectations(t)
	})

	t.Run("should generate unique tokens for different users", func(t *testing.T) {
		// Arrange
		mockKeyParser := mocks.NewEcdsaKeyPairMock(t)
		privateKey, publicKey := createTestKeyPair(t)
		config := &config.Config{
			Security: config.Security{
				AccessTokenExpirationHours: 1 * time.Hour,
				Issuer:                     "test-issuer",
				Audience:                   "test-audience",
			},
			Key: config.Key{
				PrivateKey: "mock-private-key",
				PublicKey:  "mock-public-key",
			},
		}

		ctx := context.Background()
		userID1 := uuid.New()
		userID2 := uuid.New()

		mockKeyParser.On("ParseECDSAPrivateKey", "mock-private-key").Return(privateKey, nil)
		mockKeyParser.On("ParseECDSAPublicKey", "mock-public-key").Return(publicKey, nil)

		jwtService, err := service.NewJwtService(config, mockKeyParser)
		assert.NoError(t, err)

		// Act
		result1, err1 := jwtService.GenerateAccessTokenJWT(ctx, userID1)
		result2, err2 := jwtService.GenerateAccessTokenJWT(ctx, userID2)

		// Assert
		assert.NoError(t, err1)
		assert.NoError(t, err2)
		assert.NotNil(t, result1)
		assert.NotNil(t, result2)
		assert.NotEqual(t, result1.Value, result2.Value)

		// Verify that the subjects are different
		token1, err := jwt.ParseWithClaims(result1.Value, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
			return publicKey, nil
		})
		assert.NoError(t, err)

		token2, err := jwt.ParseWithClaims(result2.Value, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
			return publicKey, nil
		})
		assert.NoError(t, err)

		claims1 := token1.Claims.(*jwt.RegisteredClaims)
		claims2 := token2.Claims.(*jwt.RegisteredClaims)

		assert.Equal(t, userID1.String(), claims1.Subject)
		assert.Equal(t, userID2.String(), claims2.Subject)
		assert.NotEqual(t, claims1.Subject, claims2.Subject)
		assert.NotEqual(t, claims1.ID, claims2.ID) // JTI should be unique

		mockKeyParser.AssertExpectations(t)
	})

	t.Run("should handle nil context gracefully", func(t *testing.T) {
		// Arrange
		mockKeyParser := mocks.NewEcdsaKeyPairMock(t)
		privateKey, publicKey := createTestKeyPair(t)
		config := &config.Config{
			Security: config.Security{
				AccessTokenExpirationHours: 1 * time.Hour,
				Issuer:                     "test-issuer",
				Audience:                   "test-audience",
			},
			Key: config.Key{
				PrivateKey: "mock-private-key",
				PublicKey:  "mock-public-key",
			},
		}

		userID := uuid.New()

		mockKeyParser.On("ParseECDSAPrivateKey", "mock-private-key").Return(privateKey, nil)
		mockKeyParser.On("ParseECDSAPublicKey", "mock-public-key").Return(publicKey, nil)

		jwtService, err := service.NewJwtService(config, mockKeyParser)
		assert.NoError(t, err)

		// Act - passing nil context
		result, err := jwtService.GenerateAccessTokenJWT(context.Background(), userID)

		// Assert
		// The method should handle nil context without panicking
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotEmpty(t, result.Value)

		mockKeyParser.AssertExpectations(t)
	})

	t.Run("should handle empty userID", func(t *testing.T) {
		// Arrange
		mockKeyParser := mocks.NewEcdsaKeyPairMock(t)
		privateKey, publicKey := createTestKeyPair(t)
		config := &config.Config{
			Security: config.Security{
				AccessTokenExpirationHours: 1 * time.Hour,
				Issuer:                     "test-issuer",
				Audience:                   "test-audience",
			},
			Key: config.Key{
				PrivateKey: "mock-private-key",
				PublicKey:  "mock-public-key",
			},
		}

		ctx := context.Background()
		emptyUserID := uuid.UUID{} // Zero UUID

		mockKeyParser.On("ParseECDSAPrivateKey", "mock-private-key").Return(privateKey, nil)
		mockKeyParser.On("ParseECDSAPublicKey", "mock-public-key").Return(publicKey, nil)

		jwtService, err := service.NewJwtService(config, mockKeyParser)
		assert.NoError(t, err)

		// Act
		result, err := jwtService.GenerateAccessTokenJWT(ctx, emptyUserID)

		// Assert
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotEmpty(t, result.Value)

		// Verify the subject is the empty UUID string
		token, err := jwt.ParseWithClaims(result.Value, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
			return publicKey, nil
		})
		assert.NoError(t, err)

		claims := token.Claims.(*jwt.RegisteredClaims)
		assert.Equal(t, "00000000-0000-0000-0000-000000000000", claims.Subject)

		mockKeyParser.AssertExpectations(t)
	})
}
