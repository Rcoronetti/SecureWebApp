package com.example.securewebapp.controller;

import com.example.securewebapp.model.User;
import com.example.securewebapp.repository.UserRepository;
import com.example.securewebapp.security.UserPrincipal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/me")
    public User getCurrentUser(@AuthenticationPrincipal UserPrincipal userPrincipal) {
        return userRepository.findById(userPrincipal.getId())
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));
    }

    @GetMapping("/hello")
    public String hello() {
        return "Oi, usuário autenticado!";
    }
}