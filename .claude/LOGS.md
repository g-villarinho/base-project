---
globs: *.go
alwaysApply: false
---
# Regras para Escrita de Testes em Go

Este documento descreve as diretrizes e o padrão a ser seguido ao escrever testes para os serviços da aplicação.

## 1. Estrutura de logs

- Para cada camada da aplicação, como `repository/user.go`, haverá um log que descreve a entidade manipulada e a camada. 
- O log para a camada deverá ser injetado na dependência.
- Para cada função dentro da camada, haverá um log que descreve o nome da função.

Exemplo:

```go

type UserRepository interface {
    // ...métodos
}

type userRepository struct {
    // ...dependências
    logger *slog.Logger
}

func NewUserRepository(
    // ...argumetos da dependência
    logger *slog.Logger
) UserRepository {
    return &userRepository{
        // ...injeta as dependências
        logger: logger.With(slog.String("user", "repository"))
    }
}

func(r *userRepository) CreateUser(
    // ...parametros
) {
    log := r.Logger.With(slog.String("func", "CreateUser"))
    // ...resto da função
}
```

## 2. Níveis de logs

### Info

- Utilizado exclusivamente para indicar que uma ação foi executada com sucesso, sem erros.
- Deve ser registrado apenas nas camadas externas da aplicação (ex.: handler), para fornecer visibilidade sobre o fluxo principal sem poluir os logs internos.

### Warn

- Utilizado para indicar situações inesperadas ou anômalas, mas que não interrompem o funcionamento normal da aplicação.
- Pode ser usado em qualquer camada (handler, service, repository), sempre que for necessário alertar sobre comportamento fora do esperado.

### Error

- Utilizado para registrar falhas que impactam diretamente a execução da ação, exigindo tratamento ou retorno de erro.
- Pode ser usado em qualquer camada, sempre acompanhado de contexto suficiente para facilitar a identificação e correção do problema.

## 3. Formato das mensagen do log

- Evite mensagens vagas como `error in repository`
- Faça mensagens mais descritivas como `Failed to save entity in database`
- Não inclua infomações sensíveis nos logs, como senha, ID ou email
- Todo log da camada ERROR tem que vir a descrição do erro usando `err.Error()`

Exemplo:

```go

func DoSomething() {
    //... código
    if err != nil {
        log.Error("error description", slog.String("error", err.Error()))
    // ... tratamento do erro
    }

    //... código
    //caso seja um log de nivel Wanr
    if err != nil { 
        log.Wanr("error description")
    }
}

```

## 4. Escrita das mensagens do log

- Frases no presente e em voz ativa, por exemplo, `Starting server`, `User authenticated successfully`
- Verbos no infinitivo ou gerúndio
- Não usar primeira pessoa
- Mensagem curta e clara, sempre indicando ação + alvo

Exemplos:

"Starting server on port 8080"
"Application loaded successfully"
"Failed to connect to database"
"User authenticated successfully"
"Failed to save user"