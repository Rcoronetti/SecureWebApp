package com.example.securewebapp.repository;

import com.example.securewebapp.model.Token;
import com.example.securewebapp.model.User;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByTokenValue(String tokenValue);

    List<Token> findAllValidTokenByUser(Long userId);

    void deleteByUser(User user);
}