package com.example.securewebapp.service;

import com.example.securewebapp.model.User;
import com.example.securewebapp.repository.UserRepository;
import com.example.securewebapp.security.JwtTokenProvider;
import com.example.securewebapp.security.UserPrincipal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

    @Autowired
    UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.info("Tentando carregar usuário: {}", username);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    logger.error("Usuário não encontrado: {}", username);
                    return new UsernameNotFoundException("Usuário não encontrado: " + username);
                });
        logger.info("Usuário encontrado: {}, Email verificado: {}", username, user.isEmailVerified());
        return UserPrincipal.create(user);
    }

    public UserDetails loadUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado com o  id : " + id));

        return UserPrincipal.create(user);
    }
}