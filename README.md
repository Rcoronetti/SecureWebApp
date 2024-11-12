# SecureWebApp

## Objetivo do Projeto

Desenvolver uma aplicação web segura que implemente autenticação stateless com tokens JWT, autorização de usuários e integração com um provedor OAuth para login. O sistema deve armazenar credenciais de forma segura e gerenciar a validade e revogação de tokens.

## Requisitos Funcionais

1. **Autenticação:**
   - Fluxo de autenticação stateless utilizando JWT.
   - Usuários se autenticam com e-mail e senha.
   - Token JWT é devolvido após autenticação bem-sucedida.

2. **Autorização:**
   - Implementação de guards de navegação no cliente.
   - Uso de gates ou policies no servidor para controle de permissões.

3. **Armazenamento Seguro de Credenciais:**
   - Uso de hash seguro (bcrypt) para armazenar senhas.

4. **Manuseio de Tokens:**
   - Gestão da validade e revogação de tokens.

5. **OAuth 2.0:**
   - Integração com provedor OAuth (Google ou Facebook).

## Tecnologias Utilizadas

- **Backend:**
  - Java 23
  - Spring Boot 3
  - Spring Security
  - JWT para autenticação
  - OAuth 2.0 para autorização
  - Bcrypt para hashing de senhas

- **Frontend:**
  - Framework de sua escolha (ex.: React, Angular, Vue.js)
  - Estilização criativa e responsiva

## Estrutura de Pastas
SecureWebApp/ │ ├── backend/ │ ├── src/ │ │ ├── main/ │ │ │ ├── java/com/example/securewebapp/ │ │ │ ├── resources/ │ │ │ └── application.properties │ │ └── test/ │ └── build.gradle │ ├── frontend/ │ ├── src/ │ └── package.json │ └── README.md


## Configurações e Comandos

1. **Premissas:**
   - Java 23 instalado.
   - Gradle ou Maven para gerenciamento de dependências.
   - Node.js e npm/yarn para o frontend.

2. **Iniciar o Backend:**
   - Navegue para a pasta `backend`.
   - Execute `./gradlew bootRun` ou `mvn spring-boot:run`.

3. **Iniciar o Frontend:**
   - Navegue para a pasta `frontend`.
   - Execute `npm install` ou `yarn install` para instalar dependências.
   - Execute `npm start` ou `yarn start` para iniciar o servidor de desenvolvimento.
