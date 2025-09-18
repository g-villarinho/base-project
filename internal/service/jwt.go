package service

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/g-villarinho/user-demo/config"
	"github.com/g-villarinho/user-demo/internal/model"
	"github.com/g-villarinho/user-demo/pkg/keyparser"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JwtService interface {
	GenerateAccessTokenJWT(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID) (*model.AccessToken, error)
	VerifyAccessToken(ctx context.Context, token string) (*jwt.RegisteredClaims, error)
}

type jwtService struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	config     *config.Config
}

func NewJwtService(config *config.Config, keyParser keyparser.EcdsaKeyPair) (JwtService, error) {
	privateKey, err := keyParser.ParseECDSAPrivateKey(config.Key.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse ecdsa private key: %w", err)
	}

	publicKey, err := keyParser.ParseECDSAPublicKey(config.Key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse ecdsa public key: %w", err)
	}

	return &jwtService{
		privateKey: privateKey,
		publicKey:  publicKey,
		config:     config,
	}, nil
}

func (j *jwtService) GenerateAccessTokenJWT(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID) (*model.AccessToken, error) {
	now := time.Now()
	expiresAt := now.Add(j.config.Security.AccessTokenExpirationHours)

	claims := jwt.RegisteredClaims{
		Issuer:    j.config.Security.Issuer,
		Audience:  jwt.ClaimStrings{j.config.Security.Audience},
		Subject:   userID.String(),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        uuid.New().String(),
	}

	customClaims := model.CustomClaims {
    RegisteredClaims: claims,
		SessionID: sessionID.String(),
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodES256, customClaims).SignedString(j.privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign token: %w", err)
	}

	return &model.AccessToken{
		Value:     token,
		ExpiresAt: expiresAt,
	}, nil
}

func (j *jwtService) VerifyAccessToken(ctx context.Context, tokenString string) (*jwt.RegisteredClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}
