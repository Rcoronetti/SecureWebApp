package com.example.securewebapp.service;

import com.example.securewebapp.model.User;
import com.example.securewebapp.repository.UserRepository;
import com.example.securewebapp.security.JwtTokenProvider;
import com.example.securewebapp.security.UserPrincipal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashSet;
import java.util.UUID;

@Service
public class AuthService {

    @Autowired
    private TokenService tokenService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private SecurityLogService securityLogService;

    @Autowired
    private JavaMailSender mailSender;

    public String authenticateUser(String username, String password) {
        try {
            // verifica se o usuário existe e se o e-mail foi verificado
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

            if (!user.isEmailVerified()) {
                throw new RuntimeException("Por favor, verifique seu e-mail antes de fazer login");
            }

            // Tenta autenticar o usuário
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));

            // Se a autenticação for bem-sucedida, procede com a geração de tokens
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = tokenProvider.generateToken(authentication);

            // Registra a tentativa de login bem-sucedida
            securityLogService.logLoginAttempt(username, true);

            return jwt;
        } catch (Exception e) {
            // Registra a tentativa de login mal-sucedida
            securityLogService.logLoginAttempt(username, false);

            // Se a exceção foi devido a e-mail não verificado, lança essa exceção
            // específica
            if (e.getMessage().contains("verifique seu e-mail")) {
                throw new RuntimeException("Por favor, verifique seu e-mail antes de fazer login", e);
            }

            // Para outras exceções, lança uma mensagem genérica de erro de autenticação
            throw new RuntimeException("Falha na autenticação. Verifique suas credenciais.", e);
        }
    }

    public String refreshToken(String refreshToken) {
        Long userId = tokenProvider.getUserIdFromJWT(refreshToken);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        if (refreshToken.equals(user.getRefreshToken()) && tokenProvider.validateToken(refreshToken)) {
            String newToken = tokenProvider.generateToken(userId);
            securityLogService.logRefreshToken(user.getUsername());
            return newToken;
        } else {
            throw new RuntimeException("Atualização de token inválida");
        }
    }

    public boolean registerUser(String username, String email, String password) {
        if (userRepository.findByUsername(username).isPresent() || userRepository.findByEmail(email).isPresent()) {
            return false;
        }

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setEmailVerificationToken(generateVerificationToken());
        user.setEmailVerificationTokenExpiry(LocalDateTime.now().plusHours(24));
        userRepository.save(user);

        sendVerificationEmail(user.getEmail(), user.getEmailVerificationToken());
        return true;
    }

    private String generateVerificationToken() {
        return UUID.randomUUID().toString();
    }

    private void sendVerificationEmail(String email, String token) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("verifique seu e-mail");
        message.setText("Por favor, clique no link abaixo para verificar seu email :\n"
                + "http://localhost:8080/api/auth/verify-email?token=" + token);
        mailSender.send(message);
    }

    public void initiatePasswordReset(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        String token = generatePasswordResetToken();
        user.setPasswordResetToken(token);
        user.setPasswordResetTokenExpiry(LocalDateTime.now().plusHours(1));
        userRepository.save(user);

        sendPasswordResetEmail(user.getEmail(), token);
    }

    private String generatePasswordResetToken() {
        return UUID.randomUUID().toString();
    }

    public boolean verifyEmail(String token) {
        User user = userRepository.findByEmailVerificationToken(token)
                .orElseThrow(() -> new RuntimeException("Token de verificação inválido"));

        if (user.getEmailVerificationTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Token de verificação expirado");
        }

        user.setEmailVerified(true);
        user.setEmailVerificationToken(null);
        user.setEmailVerificationTokenExpiry(null);
        userRepository.save(user);

        return true;
    }

    private void sendPasswordResetEmail(String email, String token) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Redefinição de senha solicitada");
        message.setText("Para resetar sua senha, clique no link: http://localhost:8080/reset-password?token=" + token);
        mailSender.send(message);
    }

    public void resetPassword(String token, String newPassword) {
        User user = userRepository.findByPasswordResetTokenAndPasswordResetTokenExpiryAfter(token, LocalDateTime.now())
                .orElseThrow(() -> new RuntimeException("Token de redefinição de senha inválido ou expirado"));

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setPasswordResetToken(null);
        user.setPasswordResetTokenExpiry(null);
        userRepository.save(user);
    }

    // Método de teste para envio de e-mail
    public void testEmail() {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo("seu-email@example.com");
        message.setSubject("Teste de E-mail");
        message.setText("Este é um e-mail de teste da aplicação Spring Boot.");
        mailSender.send(message);
    }

    public void logout(String authToken) {
        tokenService.blacklistToken(authToken);
    }
}