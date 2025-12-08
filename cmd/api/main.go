// @title           Base Project API
// @version         1.0
// @description     A Clean Architecture REST API with authentication, user management, and session handling
// @description     This API follows RFC 7807 Problem JSON format for error responses
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.url    http://www.example.com/support
// @contact.email  support@example.com

// @license.name  MIT
// @license.url   https://opensource.org/licenses/MIT

// @host      localhost:5001
// @BasePath  /

// @securityDefinitions.apikey CookieAuth
// @in cookie
// @name base-project:session
// @description Session-based authentication using secure HTTP-only cookies

// @tag.name Auth
// @tag.description Authentication operations including registration, login, password management, and email verification

// @tag.name User
// @tag.description User profile management operations

// @tag.name Sessions
// @tag.description Session management and revocation operations

// @tag.name Dev
// @tag.description Development utilities (only available in development environment)

package main

import (
	"github.com/g-villarinho/base-project/internal/api"
	"github.com/g-villarinho/base-project/pkg/injector"
)

func main() {
	container := api.ProvideDependencies()

	server := injector.Resolve[*api.API](container)

	server.Start()
}
