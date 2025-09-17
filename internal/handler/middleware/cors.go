package middleware

import (
	"github.com/g-villarinho/user-demo/config"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func Cors(config *config.Config) echo.MiddlewareFunc {
	return middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     config.Cors.AllowedOrigins,
		AllowMethods:     config.Cors.AllowedMethods,
		AllowHeaders:     config.Cors.AllowedHeaders,
		AllowCredentials: true,
	})
}
