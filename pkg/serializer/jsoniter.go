package serializer

import (
	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo/v4"
)

type Serializer struct{}

func NewSerializer() *Serializer {
	return &Serializer{}
}

func (s *Serializer) Serialize(c echo.Context, v any, indent string) error {
	enc := jsoniter.NewEncoder(c.Response())
	if indent != "" {
		enc.SetIndent("", indent)
	}
	return enc.Encode(v)
}

func (s *Serializer) Deserialize(c echo.Context, v any) error {
	return jsoniter.NewDecoder(c.Request().Body).Decode(v)
}
