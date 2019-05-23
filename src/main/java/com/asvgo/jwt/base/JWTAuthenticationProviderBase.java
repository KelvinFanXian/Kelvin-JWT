package com.asvgo.jwt.base;

import com.asvgo.jwt.base.support.JWTUtils;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * @author Kelvin范显
 * @createDate 2018年01月08日
 */
public abstract class JWTAuthenticationProviderBase<T extends JWTUserBase> implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        T jwtUser = getJWTUser(authentication);
        Collection<? extends GrantedAuthority> authorities = JWTUtils.role2SimpleGrantedAuthority(jwtUser.getRoles());
        Authentication auth = new UsernamePasswordAuthenticationToken(jwtUser.getId(), authentication.getCredentials(), authorities);
        return auth;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

    protected abstract T getJWTUser(Authentication authentication);
}