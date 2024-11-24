package com.example.securewebapp.controller;

import com.example.securewebapp.dto.AuthResponse;
import com.example.securewebapp.dto.LoginRequest;
import com.example.securewebapp.dto.RegisterRequest;
import com.example.securewebapp.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody RegisterRequest registerRequest) {
        if (authService.registerUser(registerRequest.getUsername(), registerRequest.getEmail(),
                registerRequest.getPassword())) {
            return ResponseEntity.ok("Usuario registrado com suscesso");
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
}