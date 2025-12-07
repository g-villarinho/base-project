package main

import (
	"log"

	"github.com/g-villarinho/base-project/internal/api"
	"github.com/g-villarinho/base-project/pkg/injector"
)

func main() {
	container := api.ProvideDependencies()

	server := injector.Resolve[*api.API](container)

	log.Fatal(server.Start())
}
