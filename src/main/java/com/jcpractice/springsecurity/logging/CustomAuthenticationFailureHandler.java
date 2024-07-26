package com.jcpractice.springsecurity.logging;

import com.jcpractice.springsecurity.user.User;
import com.jcpractice.springsecurity.user.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private static final Logger logger = LoggerFactory.getLogger(CustomAuthenticationFailureHandler.class);

    @Autowired
    private UserRepository userRepository;

    private ConcurrentHashMap<String, FailedLoginAttempt> failedAttempts = new ConcurrentHashMap<>();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        String username = request.getParameter("username");
        if (username != null) {
            logger.warn("Login failed for user {}", username);

            failedAttempts.putIfAbsent(username, new FailedLoginAttempt());
            FailedLoginAttempt attempt = failedAttempts.get(username);
            attempt.incrementAttempts();

            if (attempt.getAttempts() >= 3) {
                User user = userRepository.findByUsername(username).get();
                if (user != null) {
                    user.setAccountNonLocked(false);
                    user.setLockTime(LocalDateTime.now());
                    userRepository.save(user);
                    logger.warn("Account locked for user {} due to too many failed login attempts", username);
                }
            }
        }
        // Continue with the default behavior
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed");
    }

    private static class FailedLoginAttempt {
        private int attempts;

        public int getAttempts() {
            return attempts;
        }

        public void incrementAttempts() {
            attempts++;
        }
    }
}
