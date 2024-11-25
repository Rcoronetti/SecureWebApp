package com.example.securewebapp.config;

import io.github.cdimascio.dotenv.Dotenv;
import jakarta.annotation.PostConstruct;

import org.springframework.context.annotation.Configuration;

@Configuration
public class EnvConfig {

    @PostConstruct
    public void init() {
        Dotenv dotenv = Dotenv.load();
        System.setProperty("MAILTRAP_USERNAME", dotenv.get("MAILTRAP_USERNAME"));
        System.setProperty("MAILTRAP_PASSWORD", dotenv.get("MAILTRAP_PASSWORD"));
    }
}