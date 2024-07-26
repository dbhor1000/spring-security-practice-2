package com.jcpractice.springsecurity.authentication;

import com.jcpractice.springsecurity.userDetails.CustomUserDetails;
import com.jcpractice.springsecurity.userDetails.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private ConcurrentHashMap<String, FailedLoginAttempt> failedAttempts = new ConcurrentHashMap<>();

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        if (!userDetails.isAccountNonLocked()) {
            LocalDateTime lockTime = ((CustomUserDetails) userDetails).getLockTime();
            if (lockTime != null && lockTime.plus(5, ChronoUnit.MINUTES).isAfter(LocalDateTime.now())) {
                throw new LockedException("Account is locked. Please try again later.");
            } else {
                ((CustomUserDetails) userDetails).setAccountNonLocked(true);
                ((CustomUserDetails) userDetails).setLockTime(null);
                userDetailsService.saveUser(userDetails);
            }
        }

        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            failedAttempts.putIfAbsent(username, new FailedLoginAttempt());
            FailedLoginAttempt attempt = failedAttempts.get(username);
            attempt.incrementAttempts();

            if (attempt.getAttempts() >= 3) {
                ((CustomUserDetails) userDetails).setAccountNonLocked(false);
                ((CustomUserDetails) userDetails).setLockTime(LocalDateTime.now());
                userDetailsService.saveUser(userDetails);
                throw new LockedException("Account is locked due to too many failed login attempts.");
            }

            throw new BadCredentialsException("Invalid username or password.");
        }

        failedAttempts.remove(username);
        return new UsernamePasswordAuthenticationToken(userDetails, password, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
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