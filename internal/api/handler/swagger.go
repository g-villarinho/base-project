package handler

import (
	"html/template"
	"net/http"

	"github.com/labstack/echo/v4"
)

type SwaggerHandler struct{}

func NewSwaggerHandler() *SwaggerHandler {
	return &SwaggerHandler{}
}

// ServeSwaggerJSON serves the generated swagger.json file
func (h *SwaggerHandler) ServeSwaggerJSON(c echo.Context) error {
	return c.File("./docs/swagger.json")
}

// ServeScalarUI serves the Scalar documentation UI via CDN
func (h *SwaggerHandler) ServeScalarUI(c echo.Context) error {
	html := `<!doctype html>
<html>
  <head>
    <title>Base Project API Documentation</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script
      id="api-reference"
      data-url="/swagger/doc.json"
      data-configuration='{
        "theme": "default",
        "layout": "modern",
        "showSidebar": true,
        "hideModels": false,
        "hideDownloadButton": false,
        "authentication": {
          "preferredSecurityScheme": "CookieAuth"
        }
      }'
    ></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>`

	tmpl := template.Must(template.New("scalar").Parse(html))
	c.Response().Header().Set(echo.HeaderContentType, echo.MIMETextHTMLCharsetUTF8)
	c.Response().WriteHeader(http.StatusOK)
	return tmpl.Execute(c.Response().Writer, nil)
}
