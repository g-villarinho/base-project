package config

import (
	"errors"
	"fmt"

	"github.com/Netflix/go-env"
	"github.com/joho/godotenv"
)

func NewConfig(envFile string) (*Config, error) {
	var config Config

	if err := loadConfigs(&config, envFile); err != nil {
		return nil, fmt.Errorf("load environment variables: %w", err)
	}

	return &config, nil
}

func loadConfigs(config *Config, envFile string) error {
	if config == nil {
		return errors.New("environment is nil")
	}

	if err := godotenv.Load(envFile); err != nil {
		return err
	}

	if _, err := env.UnmarshalFromEnviron(config); err != nil {
		return fmt.Errorf("load environment variables: %w", err)
	}

	return nil
}
