package com.example.securewebapp.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import com.example.securewebapp.service.SecurityLogService;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class RateLimitFilter implements Filter {

    @Autowired
    private SecurityLogService securityLogService;

    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    private static final Logger logger = LoggerFactory.getLogger(RateLimitFilter.class);

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;
        String path = httpRequest.getRequestURI();

        logger.info("Requisição recebida para o path: {}", path);

        if (isStaticResource(path)) {
            logger.info("Recurso estático detectado, ignorando limite de taxa para: {}", path);
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        String ipAddress = getClientIP(httpRequest);
        Bucket bucket = buckets.computeIfAbsent(ipAddress, this::newBucket);

        if (bucket.tryConsume(1)) {
            filterChain.doFilter(servletRequest, servletResponse);
        } else {
            httpResponse.setStatus(429);
            httpResponse.getWriter().write("Muitas requisições. Por favor, tente novamente mais tarde.");
            securityLogService.logRateLimitExceeded(ipAddress);
        }
    }

    private boolean isStaticResource(String path) {
        return path.startsWith("/css/") ||
                path.startsWith("/js/") ||
                path.equals("/") ||
                path.equals("/index.html") ||
                path.equals("/login.html") ||
                path.equals("/register.html");
    }

    private Bucket newBucket(String ip) {
        return Bucket.builder()
                .addLimit(Bandwidth.classic(20, Refill.intervally(20, Duration.ofMinutes(1))))
                .build();
    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
}