package com.asvgo.jwt.base.support;

import com.asvgo.jwt.base.JWTTokenUtilBase;
import com.asvgo.jwt.base.JWTUserBase;
import com.asvgo.jwt.base.JWTUserFactoryBase;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

/**
 * @author Kelvin范显
 * @createDate 2018年01月08日
 */
@Service
public class AuthService{
    private AuthenticationManager authenticationManager;
    private JWTTokenUtilBase jwtTokenUtil;
    private JWTUserFactoryBase jwtUserFactory;

    @Autowired
    public AuthService(
            AuthenticationManager authenticationManager,
            JWTTokenUtilBase jwtTokenUtil,
            JWTUserFactoryBase jwtUserFactory) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenUtil = jwtTokenUtil;
        this.jwtUserFactory = jwtUserFactory;
    }

    /**
     * 根据用户名密码生成token
     * @param username
     * @param password
     * @return
     */
    public String login(String username, String password) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        // 进行认证
        final Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 生成token
        return jwtUserFactory.generateToken(authentication);
    }

    /**
     * 通过老token获取新token
     * @param oldToken
     * @return
     */
    public String refresh(String oldToken){
        Authentication authentication = jwtTokenUtil.getAuthentication(oldToken);
        JWTUserBase user = jwtUserFactory.create(authentication);
        if (user!=null&&jwtTokenUtil.canTokenBeRefreshed(oldToken, user.getLastPasswordResetDate())){
            return jwtTokenUtil.refreshToken(oldToken);
        }
        return null;
    }
}