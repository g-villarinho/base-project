package config

import "time"

const (
	Development = "development"
	Staging     = "staging"
	Production  = "production"
)

type Config struct {
	Env         string `mapstructure:"env"`
	Server      Server `mapstructure:"server"`
	Security    Security `mapstructure:"security"`
	RateLimit   RateLimit `mapstructure:"ratelimit"`
	Cors        Cors `mapstructure:"cors"`
	URL         URL `mapstructure:"url"`
	SqlLite     SqlLite `mapstructure:"sqlite"`
	Resend      Resend `mapstructure:"resend"`
	Key         Key `mapstructure:"key"`
	Session     Session `mapstructure:"session"`
	ShowSQLLogs bool `mapstructure:"showsqllogs"`
}

type Server struct {
	Port int    `mapstructure:"port"`
	Host string `mapstructure:"host"`
}

type SqlLite struct {
	DatabaseName string        `mapstructure:"databasename"`
	MaxConn      int           `mapstructure:"maxconn"`
	MaxIdle      int           `mapstructure:"maxidle"`
	MaxLifeTime  time.Duration `mapstructure:"maxlifetime"`
}

type Security struct {
	AccessTokenExpirationHours time.Duration `mapstructure:"accesstokenexpirationhours"`
	Issuer                     string        `mapstructure:"issuer"`
	Audience                   string        `mapstructure:"audience"`
}

type RateLimit struct {
	MaxRequests int           `mapstructure:"maxrequests"`
	Window      time.Duration `mapstructure:"window"`
}

type Cors struct {
	AllowedOrigins []string `mapstructure:"allowedorigins"`
	AllowedMethods []string `mapstructure:"allowedmethods"`
	AllowedHeaders []string `mapstructure:"allowedheaders"`
}

type Key struct {
	PrivateKey string `mapstructure:"privatekey"`
	PublicKey  string `mapstructure:"publickey"`
}

type URL struct {
	APIBaseURL string `mapstructure:"apibaseurl"`
	APPBaseURL string `mapstructure:"appbaseurl"`
}

type Resend struct {
	APIKey  string        `mapstructure:"apikey"`
	Domain  string        `mapstructure:"domain"`
	Timeout time.Duration `mapstructure:"timeout"`
}

type Session struct {
	Secret         string        `mapstructure:"secret"`
	Duration       time.Duration `mapstructure:"duration"`
	TokenSize      int           `mapstructure:"tokensize"`
	CookieName     string        `mapstructure:"cookiename"`
	CookieSecure   bool          `mapstructure:"cookiesecure"`
	CookieSameSite string        `mapstructure:"cookiesamesite"`
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
