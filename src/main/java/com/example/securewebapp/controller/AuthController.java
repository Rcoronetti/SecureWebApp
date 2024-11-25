package com.example.securewebapp.controller;

import com.example.securewebapp.dto.AuthResponse;
import com.example.securewebapp.dto.LoginRequest;
import com.example.securewebapp.dto.PasswordResetRequest;
import com.example.securewebapp.dto.RegisterRequest;
import com.example.securewebapp.service.AuthService;
import com.example.securewebapp.service.SecurityLogService;
import com.example.securewebapp.dto.RefreshTokenRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.example.securewebapp.service.TokenService;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private SecurityLogService securityLogService;

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody RegisterRequest registerRequest) {
        if (authService.registerUser(registerRequest.getUsername(), registerRequest.getEmail(),
                registerRequest.getPassword())) {
            return ResponseEntity
                    .ok("Usuário registrado com sucesso. Por favor, cheque seu email para verificar sua conta.");
        } else {
            return ResponseEntity.badRequest().body("Username ou e-mail já cadastrado");
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

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        String jwt = authService.authenticateUser(loginRequest.getUsername(), loginRequest.getPassword());
        return ResponseEntity.ok(new AuthResponse(jwt));
    }

    @GetMapping("/test")
    public ResponseEntity<String> testEndpoint() {
        return ResponseEntity.ok("Teste de endpoint");
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(@RequestHeader("Authorization") String token, HttpServletRequest request) {
        if (token != null && token.startsWith("Bearer ")) {
            String jwt = token.substring(7);
            tokenService.blacklistToken(jwt);
            securityLogService.logLogout(request.getUserPrincipal().getName());
            securityLogService.logTokenBlacklisted(jwt);
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