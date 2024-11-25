package com.example.securewebapp.model;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "tokens")
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String tokenValue;

    @Enumerated(EnumType.STRING)
    private TokenType tokenType;

    @Column(nullable = false)
    private boolean revoked;

    @Column(nullable = false)
    private Instant expiryDate;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    public enum TokenType {
        ACESSO,
        ATUALIZACAO
    }

    // Construtores
    public Token() {
    }

    public Token(String tokenValue, TokenType tokenType, boolean revoked, Instant expiryDate, User user) {
        this.tokenValue = tokenValue;
        this.tokenType = tokenType;
        this.revoked = revoked;
        this.expiryDate = expiryDate;
        this.user = user;
    }

    // Getters e Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getTokenValue() {
        return tokenValue;
    }

    public void setTokenValue(String tokenValue) {
        this.tokenValue = tokenValue;
    }

    public TokenType getTokenType() {
        return tokenType;
    }

    public void setTokenType(TokenType tokenType) {
        this.tokenType = tokenType;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }

    public Instant getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(Instant expiryDate) {
        this.expiryDate = expiryDate;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    @Override
    public String toString() {
        return "Token{" +
                "id=" + id +
                ", tokenValue='" + tokenValue + '\'' +
                ", tokenType=" + tokenType +
                ", revoked=" + revoked +
                ", expiryDate=" + expiryDate +
                ", userId=" + (user != null ? user.getId() : null) +
                '}';
    }
}