package com.jcpractice.springsecurity.userDetails;

import com.jcpractice.springsecurity.user.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;

public class CustomUserDetails implements UserDetails {

    private final User user;

    public CustomUserDetails(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getAuthorities();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return user.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public LocalDateTime getLockTime() {
        return user.getLockTime();
    }

    public void setAccountNonLocked(boolean accountNonLocked) {
        user.setAccountNonLocked(accountNonLocked);
    }

    public void setLockTime(LocalDateTime lockTime) {
        user.setLockTime(lockTime);
    }

    public User getUser() {
        return user;
    }
}
