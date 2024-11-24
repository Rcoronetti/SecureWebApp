package com.example.securewebapp.controller;

import com.example.securewebapp.dto.AuthResponse;
import com.example.securewebapp.dto.LoginRequest;
import com.example.securewebapp.dto.RegisterRequest;
import com.example.securewebapp.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.example.securewebapp.service.TokenService;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private TokenService tokenService;

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody RegisterRequest registerRequest) {
        if (authService.registerUser(registerRequest.getUsername(), registerRequest.getEmail(),
                registerRequest.getPassword())) {
            return ResponseEntity.ok("Usuário registrado com suscesso");
        } else {
            return ResponseEntity.badRequest().body("Username ou email já está em uso");
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

    @GetMapping("/api/user/profile")
    public ResponseEntity<String> getUserProfile() {
        return ResponseEntity.ok("Dados do usuário");
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(@RequestHeader("Authorization") String token) {
        if (token != null && token.startsWith("Bearer ")) {
            String jwt = token.substring(7);
            tokenService.blacklistToken(jwt);
            return ResponseEntity.ok("Logout realizado com sucesso");
        }
        return ResponseEntity.badRequest().body("token inválido");
    }
}