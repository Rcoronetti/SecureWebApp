package com.example.securewebapp.repository;

import com.example.securewebapp.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);

    Optional<User> findByUsername(String username);

    Optional<User> findByPasswordResetTokenAndPasswordResetTokenExpiryAfter(String token, LocalDateTime date);

    Optional<User> findByEmailVerificationToken(String token);

}