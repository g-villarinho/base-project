package main

import (
	"fmt"

	"github.com/g-villarinho/base-project/config"
	"github.com/g-villarinho/base-project/internal/server"
	"github.com/g-villarinho/base-project/pkg/injector"
	"github.com/labstack/echo/v4"
)

func main() {
	container := server.ProvideDependencies()

	config := injector.Resolve[*config.Config](container)
	server := injector.Resolve[*echo.Echo](container)

	server.Logger.Fatal(server.Start(fmt.Sprintf(":%d", config.Server.Port)))
}
