package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Netflix/go-env"
	"github.com/joho/godotenv"
)

func NewConfig() (*Config, error) {
	var config Config

	if err := loadConfigs(&config); err != nil {
		return nil, fmt.Errorf("load environment variables: %w", err)
	}

	return &config, nil
}

func loadConfigs(config *Config) error {
	if config == nil {
		return errors.New("environment is nil")
	}

	if err := godotenv.Load(); err != nil {
		return err
	}

	if _, err := env.UnmarshalFromEnviron(config); err != nil {
		return fmt.Errorf("load environment variables: %w", err)
	}

	if err := loadAuthKeysFromFiles(config); err != nil {
		return fmt.Errorf("load keys from files: %w", err)
	}

	return nil
}
func loadAuthKeysFromFiles(config *Config) error {
	if config.Key.PrivateKey != "" && config.Key.PublicKey != "" {
		return nil
	}

	if config.Env == Development || config.Env == "" {
		if privateKey, err := LoadKeyFromFile("ecdsa_private.pem"); err == nil {
			config.Key.PrivateKey = privateKey
		}
		if publicKey, err := LoadKeyFromFile("ecdsa_public.pem"); err == nil {
			config.Key.PublicKey = publicKey
		}
		return nil
	}

	privateKey, err := LoadKeyFromFile("ecdsa_private.pem")
	if err != nil {
		return fmt.Errorf("load private key: %w", err)
	}

	publicKey, err := LoadKeyFromFile("ecdsa_public.pem")
	if err != nil {
		return fmt.Errorf("load public key: %w", err)
	}

	config.Key.PrivateKey = privateKey
	config.Key.PublicKey = publicKey

	return nil
}

func LoadKeyFromFile(filename string) (string, error) {
	if data, err := os.ReadFile(filename); err == nil {
		return strings.TrimSpace(string(data)), nil
	}

	_, currentFile, _, _ := runtime.Caller(0)
	baseDir := filepath.Dir(currentFile)
	fullPath := filepath.Join(baseDir, "../", filename)

	data, err := os.ReadFile(fullPath)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", fullPath, err)
	}

	return strings.TrimSpace(string(data)), nil
}
