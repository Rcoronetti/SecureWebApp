# SecureWebApp

## Visão Geral do Projeto

SecureWebApp é uma aplicação web segura construída com Spring Boot, focada em implementar autenticação e autorização robustas usando JWT (JSON Web Tokens).

## Estrutura do Projeto

### Configuração

1. **SecurityConfig**: Configura as regras de segurança da aplicação.
   - Define endpoints públicos e protegidos
   - Configura o encoder de senha

2. **application.properties**: Contém configurações cruciais do projeto.
   - Configurações do banco de dados
   - Configurações do JWT (chave secreta e tempo de expiração)

### Modelo de Dados

3. **User**: Entidade JPA que representa um usuário no sistema.
   - Armazena informações como id, username, password e roles

### Repositório

4. **UserRepository**: Interface para operações de banco de dados relacionadas aos usuários.
   - Métodos para buscar usuários por username

### Segurança

5. **JwtTokenProvider**: Responsável pela geração, validação e parsing de tokens JWT.
   - Gera tokens JWT para usuários autenticados
   - Valida tokens JWT recebidos
   - Extrai informações do usuário do token

6. **UserPrincipal**: Implementação de UserDetails do Spring Security.
   - Encapsula informações do usuário para autenticação e autorização

7. **CustomUserDetailsService**: Implementação de UserDetailsService do Spring Security.
   - Carrega detalhes do usuário para autenticação

### Aplicação Principal

8. **SecureWebAppApplication**: Ponto de entrada da aplicação Spring Boot.

## Autenticação

O sistema de autenticação foi implementado com os seguintes componentes:

- DTOs para registro, login e resposta de autenticação
- AuthService para lógica de autenticação e registro
- AuthController com endpoints para registro (/api/auth/signup) e login (/api/auth/signin)
- Configuração de segurança atualizada para permitir acesso aos endpoints de autenticação

Próximos passos incluem a implementação de um filtro JWT para processar tokens em requisições autenticadas.

## Tecnologias Utilizadas

- Spring Boot 3.3.5
- Spring Security
- JSON Web Tokens (JWT)
- JPA / Hibernate
- MySQL

## Configuração do Banco de Dados

O projeto utiliza MySQL como banco de dados. Um schema chamado `securewebapp` foi criado para armazenar as tabelas da aplicação.

## Como Executar

1. Certifique-se de ter o JDK 23 e o MySQL instalados
2. Configure as credenciais do banco de dados no `application.properties`
3. Execute `./gradlew bootRun` (Linux/Mac) ou `gradlew.bat bootRun` (Windows)

## Contribuição

Para contribuir com o projeto, por favor:
1. Faça um fork do repositório
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Faça commit das suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request
