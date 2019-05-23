package com.asvgo.jwt.base;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;

import java.util.List;

import static com.asvgo.jwt.base.support.JWTUtils.authority2Roles;


public abstract class JWTUserFactoryBase<T extends JWTUserBase>{

    @Autowired
    private JWTTokenUtilBase jwtTokenUtil;

    /**
     * 可以从 authentication 参数中获取userid和au
     * @param authentication
     * @return
     */
    public T create(Authentication authentication) {
        String userId = authentication.getName();
        List<String> roles = authority2Roles(authentication);
        return create(userId, roles);
    }

    protected abstract T create(String userId, List<String> roles);

    public String generateToken(Authentication authentication) {
        T jwtUser = create(authentication);
        return jwtTokenUtil.generateToken(jwtUser);
    }
}
