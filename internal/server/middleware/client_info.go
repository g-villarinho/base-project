package middleware

import (
	"github.com/g-villarinho/base-project/internal/model"
	"github.com/g-villarinho/base-project/internal/server/echoctx"
	"github.com/labstack/echo/v4"
)

func ClientInfo() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			clientInfo := model.ClientInfo{
				IPAddress:  c.RealIP(),
				DeviceName: req.Header.Get("Device-Name"),
				UserAgent:  req.UserAgent(),
			}
			echoctx.SetClientInfo(c, clientInfo)
			return next(c)
		}
	}
}
