package injector

import (
	"log"

	"go.uber.org/dig"
)

func Provide(container *dig.Container, constructor any, opts ...dig.ProvideOption) {
	if err := container.Provide(constructor, opts...); err != nil {
		log.Fatalf("[dig] failed to Provide: %T: %v", constructor, err)
	}
}

func Resolve[T any](c *dig.Container, opts ...dig.InvokeOption) T {
	var out T
	if err := c.Invoke(func(dep T) {
		out = dep
	}, opts...); err != nil {
		log.Fatalf("[dig] failed to Resolve: %T: %v", out, err)
	}
	return out
}
