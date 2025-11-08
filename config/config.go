package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

func NewConfig() (*Config, error) {
	v := viper.New()

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")
	v.AddConfigPath("$HOME/.base-project")

	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	setDefaults(v)

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("unable to decode config into struct: %w", err)
	}

	return &config, nil
}

func setDefaults(v *viper.Viper) {
	// General
	v.SetDefault("env", "development")
	v.SetDefault("showsqllogs", false)

	// Server
	v.SetDefault("server.port", 5001)
	v.SetDefault("server.host", "localhost")

	// Database
	v.SetDefault("sqlite.databasename", "users.db")
	v.SetDefault("sqlite.maxconn", 10)
	v.SetDefault("sqlite.maxidle", 5)
	v.SetDefault("sqlite.maxlifetime", "300s")

	// Security
	v.SetDefault("security.accesstokenexpirationhours", "2h")
	v.SetDefault("security.issuer", "users-api")
	v.SetDefault("security.audience", "users-api")

	// Rate Limit
	v.SetDefault("ratelimit.maxrequests", 100)
	v.SetDefault("ratelimit.window", "1m")

	// CORS
	v.SetDefault("cors.allowedorigins", []string{"*"})
	v.SetDefault("cors.allowedmethods", []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
	v.SetDefault("cors.allowedheaders", []string{"Content-Type", "Authorization"})

	// URL
	v.SetDefault("url.apibaseurl", "http://localhost:5001")
	v.SetDefault("url.appbaseurl", "http://localhost:5173")

	// Resend (required fields - no defaults for API key and domain)
	v.SetDefault("resend.timeout", "10s")

	// Session
	v.SetDefault("session.secret", "cjQ6A2CJ2V5g2StB6DPYA3rxfvOlKm3m")
	v.SetDefault("session.duration", "168h")
	v.SetDefault("session.tokensize", 32)
	v.SetDefault("session.cookiename", "base-project:session")
	v.SetDefault("session.cookiesecure", false)
	v.SetDefault("session.cookiesamesite", "strict")
}
