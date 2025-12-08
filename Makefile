setup: ## Instala bibliotecas necessárias do projeto
	@go install github.com/vektra/mockery/v2@v2.53.4
	@go install github.com/air-verse/air@v1.63.4
	@go install github.com/swaggo/swag/cmd/swag@v1.16.4
	@go install github.com/sqlc-dev/sqlc/cmd/sqlc@v1.30.0
	@go install gotest.tools/gotestsum@v1.13.0

run: build ## Roda o servidor com .env padrão
	@./bin/api

swagger: ## Generate Swagger/OpenAPI documentation
	@swag init -g cmd/api/main.go -o docs --parseDependency --parseInternal

docs: swagger ## Alias for swagger generation

build: swagger ## Build includes swagger generation
	@go build -o bin/api cmd/api/main.go

test: ## Executa todos os testes
	@gotestsum --format pkgname --format-hide-empty-pkg -- ./...

mocks: ## Gera mock de services, repositories e commons
	@mockery

sqlc: ## Gera código SQLC a partir das queries SQL
	@sqlc generate
