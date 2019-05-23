package com.asvgo.jwt.base.support;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Kelvin范显
 * @createDate 2018年01月05日
 */
public class JWTUtils {

    public static List<String> authority2Roles(Authentication authentication) {
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        return authorities.stream().map(authority -> authority.getAuthority()).collect(Collectors.toList());
    }

    public static List<SimpleGrantedAuthority> role2SimpleGrantedAuthority(List<String> rolesList) {
        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();
        if (rolesList != null) {
            for(String authString : rolesList) {
                SimpleGrantedAuthority grantedAuthority = new SimpleGrantedAuthority(authString);
                authorityList.add(grantedAuthority);
            }
        }
        return authorityList;
    }
}
