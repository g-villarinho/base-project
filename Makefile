setup: ## Instala bilbiotecas necessárias do projeto
	@go install github.com/gotesttools/gotestfmt/v2/cmd/gotestfmt@v2.5.0
	@go install github.com/vektra/mockery/v2@v2.53.4
	@go install github.com/air-verse/air@latest
	@go install github.com/swaggo/swag/cmd/swag@latest

run: build ## Roda o servidor com .env padrão
	@./bin/api

build:
	@go build -o bin/api cmd/api/main.go

test: ## Executa todos os testes
	@PATH=$(shell go env GOPATH)/bin:$(PATH) find . -name "*_test.go" -not -path "./vendor/*" -not -path "./.git/*" | \
	sed 's|/[^/]*$$||' | sort -u | \
	sed 's|^\./|github.com/g-villarinho/base-project/|' | \
	xargs go test -json -v | "$(shell go env GOPATH)/bin/gotestfmt" -hide successful-tests -showteststatus

mocks: ## Gera mock de services, repositories e commons
	@mockery
