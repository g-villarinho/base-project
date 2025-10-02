setup: ## Instala bilbiotecas necessárias do projeto
	@go install github.com/gotesttools/gotestfmt/v2/cmd/gotestfmt@v2.5.0
	@go install github.com/vektra/mockery/v2@v2.53.4
	@go install github.com/air-verse/air@latest
	@go install github.com/swaggo/swag/cmd/swag@latest

generate-key:  ## Gera as chaves de autenticação do projeto
	@openssl ecparam -name prime256v1 -genkey -noout -out ecdsa_private.pem
	@openssl ec -in ecdsa_private.pem -pubout -out ecdsa_public.pem

run: build
	@./bin/server

build:
	@go build -o bin/server cmd/server/main.go

test: ## Executa todos os testes
	@find . -name "*_test.go" -not -path "./vendor/*" -not -path "./.git/*" | \
	sed 's|/[^/]*$$||' | sort -u | \
	sed 's|^\./|github.com/g-villarinho/base-project/|' | \
	xargs go test -json -v | gotestfmt

tests: test ## Alias para test

mocks: ## Gera mock de services, repositories e commons
	@mockery
