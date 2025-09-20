package config

import "time"

const (
	Development = "development"
	Staging     = "staging"
	Production  = "production"
)

type Config struct {
	Env         string `env:"ENV,default=development"`
	Server      Server
	Security    Security
	RateLimit   RateLimit
	Cors        Cors
	URL         URL
	SqlLite     SqlLite
	Resend      Resend
	Key         Key
	Session     Session
	ShowSQLLogs bool `env:"SHOW_SQL_LOGS,default=false"`
}

type Server struct {
	Port int    `env:"SERVER_PORT,default=5001"`
	Host string `env:"SERVER_HOST,default=localhost"`
}

type SqlLite struct {
	DatabaseName string        `env:"DATABASE_NAME,default=users.db"`
	MaxConn      int           `env:"DATABASE_MAX_CONN,default=10"`
	MaxIdle      int           `env:"DATABASE_MAX_IDLE,default=5"`
	MaxLifeTime  time.Duration `env:"DATABASE_MAX_LIFE_TIME,default=300s"`
}

type Security struct {
	AccessTokenExpirationHours time.Duration `env:"ACCESS_TOKEN_EXPIRATION_HOURS,default=2h"`
	Issuer                     string        `env:"ISSUER,default=users-api"`
	Audience                   string        `env:"AUDIENCE,default=users-api"`
}

type RateLimit struct {
	MaxRequests int           `env:"RATE_LIMIT_REQUESTS,default=100"`
	Window      time.Duration `env:"RATE_LIMIT_WINDOW,default=1m"`
}

type Cors struct {
	AllowedOrigins []string `env:"CORS_ALLOWED_ORIGINS,default=*"`
	AllowedMethods []string `env:"CORS_ALLOWED_METHODS,default=GET|POST|PUT|DELETE|OPTIONS"`
	AllowedHeaders []string `env:"CORS_ALLOWED_HEADERS,default=Content-Type,Authorization"`
}

type Key struct {
	PrivateKey string
	PublicKey  string
}

type URL struct {
	APIBaseURL string `env:"API_BASE_URL,default=http://localhost:5001"`
	APPBaseURL string `env:"APP_BASE_URL,default=http://localhost:5173"`
}

type Resend struct {
	APIKey  string        `env:"RESEND_API_KEY,required=true"`
	Domain  string        `env:"RESEND_DOMAIN,required=true"`
	Timeout time.Duration `env:"RESEND_TIMEOUT_SECONDS,default=10s"`
}

type Session struct {
	Secret         string        `env:"SESSION_SECRET,default=cjQ6A2CJ2V5g2StB6DPYA3rxfvOlKm3m"`
	Duration       time.Duration `env:"SESSION_DURATION,default=168h"`
	TokenSize      int           `env:"SESSION_TOKEN_SIZE,default=32"`
	CookieName     string        `env:"SESSION_COOKIE_NAME,default=base-project:session"`
	CookieSecure   bool          `env:"SESSION_COOKIE_SECURE,default=false"`
	CookieSameSite string        `env:"SESSION_COOKIE_SAME_SITE,default=strict"`
}

func (e *Config) IsDevelopment() bool {
	return e.Env == Development
}

func (e *Config) IsStaging() bool {
	return e.Env == Staging
}

func (e *Config) IsProduction() bool {
	return e.Env == Production
}
