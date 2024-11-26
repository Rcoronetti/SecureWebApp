# SecureWebApp

## Visão Geral do Projeto

SecureWebApp é uma aplicação web segura construída com Spring Boot, focada em implementar autenticação e autorização robustas usando JWT (JSON Web Tokens).

## Estrutura do Projeto

### Configuração

1. **SecurityConfig**: Configura as regras de segurança da aplicação.
   - Define endpoints públicos e protegidos
   - Configura o encoder de senha
   - Configura o filtro JWT e o gerenciamento de sessão

2. **application.properties**: Contém configurações cruciais do projeto.
   - Configurações do banco de dados
   - Configurações do JWT (chave secreta e tempo de expiração)

### Modelo de Dados

3. **User**: Entidade JPA que representa um usuário no sistema.
   - Armazena informações como id, username, email, password e roles

### Repositório

4. **UserRepository**: Interface para operações de banco de dados relacionadas aos usuários.
   - Métodos para buscar usuários por username e id

### Segurança

5. **JwtTokenProvider**: Responsável pela geração, validação e parsing de tokens JWT.
   - Gera tokens JWT para usuários autenticados
   - Valida tokens JWT recebidos
   - Extrai informações do usuário do token

6. **UserPrincipal**: Implementação de UserDetails do Spring Security.
   - Encapsula informações do usuário para autenticação e autorização

7. **CustomUserDetailsService**: Implementação de UserDetailsService do Spring Security.
   - Carrega detalhes do usuário para autenticação

8. **JwtAuthenticationFilter**: Filtro para processar tokens JWT em requisições.
   - Extrai o token do cabeçalho da requisição
   - Valida o token e configura a autenticação no contexto de segurança

### Controladores

9. **AuthController**: Gerencia endpoints de autenticação.
   - `/api/auth/register`: Registro de novos usuários
   - `/api/auth/login`: Login de usuários

10. **UserController**: Gerencia endpoints relacionados ao usuário.
    - `/api/user/info`: Retorna informações do usuário autenticado

### Aplicação Principal

11. **SecureWebAppApplication**: Ponto de entrada da aplicação Spring Boot.

## Frontend

12. **login.html**: Página de login da aplicação.
13. **register.html**: Página de registro de novos usuários.
14. **dashboard.html**: Página principal após o login (protegida).

## Autenticação

O sistema de autenticação foi implementado com os seguintes componentes:

- DTOs para registro, login e resposta de autenticação
- AuthService para lógica de autenticação e registro
- Filtro JWT para processar tokens em requisições autenticadas

## Endpoints Protegidos

- GET `/api/user/info`: Retorna os detalhes do usuário atualmente autenticado

Para acessar estes endpoints, é necessário incluir o token JWT no header "Authorization" das requisições, com o prefixo "Bearer ".

## Tecnologias Utilizadas

- Spring Boot 3.3.5
- Spring Security
- JSON Web Tokens (JWT)
- JPA / Hibernate
- MySQL
- HTML/CSS/JavaScript (Frontend)

## Configuração do Banco de Dados

O projeto utiliza MySQL como banco de dados. Um schema chamado `securewebapp` deve ser criado para armazenar as tabelas da aplicação.

## Como Executar

1. Certifique-se de ter o JDK 23 e o MySQL instalados
2. Configure as credenciais do banco de dados no `application.properties`
3. Execute `./gradlew bootRun` (Linux/Mac) ou `gradlew.bat bootRun` (Windows)
4. Acesse `http://localhost:8080` no navegador

## Fluxo de Autenticação

1. O usuário se registra através da página de registro
2. Após o registro, o usuário faz login na página de login
3. Ao fazer login com sucesso, um token JWT é gerado e armazenado no localStorage do navegador
4. O usuário é redirecionado para o dashboard
5. Requisições subsequentes para endpoints protegidos incluem o token JWT no cabeçalho de autorização

## Próximos Passos

- Implementar logout no frontend e backend
- Adicionar mais funcionalidades ao dashboard
- Implementar recuperação de senha
- Melhorar o tratamento de erros e feedback ao usuário

## Contribuição

Para contribuir com o projeto, por favor:
1. Faça um fork do repositório
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Faça commit das suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request