package com.asvgo.jwt.base.support;

import com.asvgo.jwt.base.JWTTokenUtilBase;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@SuppressWarnings("SpringJavaAutowiringInspection")
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
    public static String PARAM_TOKEN = "token";

    @Autowired
    private JWTTokenUtilBase jwtTokenUtil;

    @Value("${jwt.header}")
    private String tokenHeader;

    @Value("${jwt.tokenHead}")
    private String tokenHead;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {
        String authHeader = request.getHeader(this.tokenHeader);
        if (authHeader != null && authHeader.startsWith(tokenHead)) {
            final String authToken = authHeader.substring(tokenHead.length()); // The part after "Bearer "
            setSecurityContext(authToken);
        } else if(StringUtils.hasText(request.getParameter(PARAM_TOKEN))){
            final String authToken = request.getParameter(PARAM_TOKEN);
            setSecurityContext(authToken);
        }
        chain.doFilter(request, response);
    }

    /**
     * 核心
     * 每次访问将token转为Authentication放入SecurityContextHolder
     * @param authToken
     */
    private void setSecurityContext(String authToken) {
        String userId = jwtTokenUtil.getUserIdFromToken(authToken);

        if (userId != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            //为省性能，只作token验证，授权内容从payload中解析
            Authentication authentication = jwtTokenUtil.getAuthentication(authToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
    }
}
