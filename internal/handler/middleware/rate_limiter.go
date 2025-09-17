package middleware

import (
	"github.com/g-villarinho/user-demo/config"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/time/rate"
)

func RateLimiter(config *config.Config) echo.MiddlewareFunc {
	rate := rate.Limit(config.RateLimit.MaxRequests)
	return middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(rate))
}
