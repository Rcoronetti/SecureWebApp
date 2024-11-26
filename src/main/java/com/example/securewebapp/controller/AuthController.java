package com.example.securewebapp.controller;

import com.example.securewebapp.dto.AuthResponse;
import com.example.securewebapp.dto.LoginRequest;
import com.example.securewebapp.dto.PasswordResetRequest;
import com.example.securewebapp.dto.RegisterRequest;
import com.example.securewebapp.security.JwtTokenProvider;
import com.example.securewebapp.service.AuthService;
import com.example.securewebapp.service.SecurityLogService;
import com.example.securewebapp.dto.RefreshTokenRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.example.securewebapp.service.TokenService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

    @Autowired
    private AuthService authService;

    @Autowired
    private SecurityLogService securityLogService;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody RegisterRequest registerRequest) {
        logger.info("Recebida requisição de registro para o usuário: {}", registerRequest.getUsername());
        try {
            if (authService.registerUser(registerRequest.getUsername(), registerRequest.getEmail(),
                    registerRequest.getPassword())) {
                logger.info("Usuário registrado com sucesso: {}", registerRequest.getUsername());
                return ResponseEntity
                        .ok("Usuário registrado com sucesso. Por favor, cheque seu email para verificar sua conta.");
            } else {
                logger.warn("Falha no registro do usuário: {}", registerRequest.getUsername());
                return ResponseEntity.badRequest().body("Username ou e-mail já cadastrado");
            }
        } catch (Exception e) {
            logger.error("Erro ao registrar usuário: {}", registerRequest.getUsername(), e);
            return ResponseEntity.badRequest().body("Erro ao registrar usuário: " + e.getMessage());
        }
    }

    @GetMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestParam String token) {
        try {
            authService.verifyEmail(token);
            return ResponseEntity.ok("Email verificado com sucesso");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        try {
            logger.info("Tentativa de login para o usuário: {}", loginRequest.getUsername());
            String jwt = authService.authenticateUser(loginRequest.getUsername(), loginRequest.getPassword());
            logger.info("Login bem-sucedido para o usuário: {}", loginRequest.getUsername());
            return ResponseEntity.ok(new AuthResponse(jwt));
        } catch (Exception e) {
            logger.error("Erro no login para o usuário: {}", loginRequest.getUsername(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }

    @GetMapping("/test")
    public ResponseEntity<String> testEndpoint() {
        return ResponseEntity.ok("Teste de endpoint");
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(@RequestHeader("Authorization") String token, HttpServletRequest request) {
        if (token != null && token.startsWith("Bearer ")) {
            String authToken = token.substring(7);
            authService.logout(authToken);
            securityLogService.logLogout(request.getUserPrincipal().getName());
            return ResponseEntity.ok("Logout realizado com sucesso");
        }
        return ResponseEntity.badRequest().body("Token inválido");
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        try {
            String token = authService.refreshToken(refreshTokenRequest.getRefreshToken());
            return ResponseEntity.ok(new AuthResponse(token));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody PasswordResetRequest request) {
        try {
            authService.initiatePasswordReset(request.getEmail());
            return ResponseEntity.ok("E-mail de redefinição de senha enviado com sucesso");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String token, @RequestBody PasswordResetRequest request) {
        try {
            authService.resetPassword(token, request.getNewPassword());
            return ResponseEntity.ok("Redefinição de senha realizada com sucesso");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    // Endpoint de teste para envio de e-mail
    @GetMapping("/test-email")
    public ResponseEntity<?> testEmail() {
        try {
            authService.testEmail();
            return ResponseEntity.ok("teste de e-mail enviado com sucesso");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Falha no envio do email: " + e.getMessage());
        }
    }
}