---
globs: *.go
alwaysApply: false
---
# Regras para Escrita de Testes em Go

Este documento descreve as diretrizes e o padrão a ser seguido ao escrever testes para os serviços da aplicação.

## 1. Estrutura e Nomenclatura de Arquivos

- Para cada arquivo de serviço, como `service/auth.go`, o arquivo de teste correspondente deve ser nomeado com o sufixo `_test.go`. Por exemplo, `service/auth_test.go`.
- Os arquivos de teste devem estar localizados no mesmo pacote que o arquivo que está sendo testado.

## 2. Estrutura dos Testes

- Para cada método público no serviço, deve haver uma única função de teste principal. Por exemplo, para um método `CreateOrganization` no serviço, a função de teste correspondente seria `TestOrganizationService_CreateOrganization`.
- Dentro de cada função de teste principal, os casos de teste individuais devem ser organizados usando `t.Run()`. Cada `t.Run()` deve descrever claramente o cenário que está sendo testado, seguindo o padrão "should [fazer algo] when [condição]".

Exemplo:

```go
func TestAuthService_Login(t *testing.T) {
    t.Run("should return tokens when credentials are valid", func(t *testing.T) {
        // ... corpo do teste
    })

    t.Run("should return error when email is invalid", func(t *testing.T) {
        // ... corpo do teste
    })

    t.Run("should return error when password is wrong", func(t *testing.T) {
        // ... corpo do teste
    })
}
```

## 3. Código Limpo e Reutilização

- **Testes Pequenos e Focados:** Cada sub-teste (`t.Run`) deve ter uma única responsabilidade e testar um único cenário.
- **Abstração de Configuração:** Se houver configurações ou setups repetitivos entre os testes (como a criação de mocks, inicialização de serviços, etc.), essas lógicas devem ser abstraídas em funções auxiliares (helper functions).
- **Clareza:** Os testes devem ser fáceis de ler e entender. Use nomes de variáveis descritivos e evite lógicas complexas dentro dos testes. O objetivo é que o teste sirva como uma documentação viva do comportamento do método.

## 4. Uso de Mocks

- **Dependências Mockadas:** Todas as dependências externas de um serviço, como repositórios ou outros serviços, devem ser substituídas por mocks nos testes. Isso garante o isolamento do componente que está sendo testado.
- **Localização dos Mocks:** Os mocks gerados pela ferramenta `mockery` estão localizados no diretório `internal/mocks/`. Utilize os mocks deste diretório.
- **Geração de Mocks:** Se o mock para uma interface que você precisa testar não existir no diretório `internal/mocks/`, você deve gerá-lo. Para isso, execute o comando `make mocks` na raiz do projeto. Este comando irá gerar todos os mocks definidos no arquivo de configuração `.mockery.yml`.

## 5. Fim
-- **Rode os testes:** Ao finalizar a criação de testes execute o make test para ver se todos os testes estão passando e se não estiverem conserte os que estão quebrados.