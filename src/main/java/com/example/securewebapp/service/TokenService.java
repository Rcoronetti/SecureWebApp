package com.example.securewebapp.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.securewebapp.model.Token;
import com.example.securewebapp.repository.TokenRepository;

@Service
public class TokenService {
    @Autowired
    private TokenRepository tokenRepository;

    public void blacklistToken(String tokenValue) {
        tokenRepository.findByTokenValue(tokenValue).ifPresent(token -> {
            token.setRevoked(true);
            tokenRepository.save(token);
        });
    }

    public boolean isTokenBlacklisted(String tokenValue) {
        return tokenRepository.findByTokenValue(tokenValue)
                .map(Token::isRevoked)
                .orElse(false);
    }
}