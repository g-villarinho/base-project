package serializer

import (
	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo/v4"
)

type JSONSerializer struct{}

func NewJSONSerializer() *JSONSerializer {
	return &JSONSerializer{}
}

func (s *JSONSerializer) Serialize(c echo.Context, v any, indent string) error {
	enc := jsoniter.NewEncoder(c.Response())
	if indent != "" {
		enc.SetIndent("", indent)
	}
	return enc.Encode(v)
}

func (s *JSONSerializer) Deserialize(c echo.Context, v any) error {
	return jsoniter.NewDecoder(c.Request().Body).Decode(v)
}
