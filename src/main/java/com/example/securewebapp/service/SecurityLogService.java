package com.example.securewebapp.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class SecurityLogService {
    private static final Logger logger = LoggerFactory.getLogger(SecurityLogService.class);

    public void logLoginAttempt(String username, boolean success) {
        if (success) {
            logger.info("Tentativa de login realizada com sucesso para o usuário : {}", username);
        } else {
            logger.warn("Erro na tentativa de login para o usuário : {}", username);
        }
    }

    public void logLogout(String username) {
        logger.info("Usuário deslogado: {}", username);
    }

    public void logTokenBlacklisted(String token) {
        logger.info("Token blacklisted: {}", token);
    }

    public void logUnauthorizedAccess(String endpoint, String ipAddress) {
        logger.warn("Tentativa de acesso não autorizada para {} do IP: {}", endpoint, ipAddress);
    }

    public void logRefreshToken(String username) {
        logger.info("Sucesso na atualização de token para o usuário: {}", username);
    }
}