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
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = tokenProvider.generateToken(authentication);
            String refreshToken = tokenProvider
                    .generateRefreshToken(((UserPrincipal) authentication.getPrincipal()).getId());

            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new RuntimeException("User not found"));
            user.setRefreshToken(refreshToken);
            userRepository.save(user);

            securityLogService.logLoginAttempt(username, true);
            return jwt;
        } catch (Exception e) {
            securityLogService.logLoginAttempt(username, false);
            throw e;
        }
    }

    public String refreshToken(String refreshToken) {
        Long userId = tokenProvider.getUserIdFromJWT(refreshToken);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (refreshToken.equals(user.getRefreshToken()) && tokenProvider.validateToken(refreshToken)) {
            String newToken = tokenProvider.generateToken(userId);
            securityLogService.logRefreshToken(user.getUsername());
            return newToken;
        } else {
            throw new RuntimeException("Invalid refresh token");
        }
    }

    public boolean registerUser(String username, String email, String password) {
        if (userRepository.existsByUsername(username) || userRepository.existsByEmail(email)) {
            return false;
        }

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setRoles(new HashSet<>(Collections.singletonList("USER")));

        userRepository.save(user);
        return true;
    }

    public void initiatePasswordReset(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String token = generatePasswordResetToken();
        user.setPasswordResetToken(token);
        user.setPasswordResetTokenExpiry(LocalDateTime.now().plusHours(1));
        userRepository.save(user);

        sendPasswordResetEmail(user.getEmail(), token);
    }

    private String generatePasswordResetToken() {
        return UUID.randomUUID().toString();
    }

    private void sendPasswordResetEmail(String email, String token) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Password Reset Request");
        message.setText("To reset your password, click the link: http://localhost:8080/reset-password?token=" + token);
        mailSender.send(message);
    }

    public void resetPassword(String token, String newPassword) {
        User user = userRepository.findByPasswordResetTokenAndPasswordResetTokenExpiryAfter(token, LocalDateTime.now())
                .orElseThrow(() -> new RuntimeException("Invalid or expired password reset token"));

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
}