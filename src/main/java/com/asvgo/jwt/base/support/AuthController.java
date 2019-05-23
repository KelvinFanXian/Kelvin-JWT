package com.asvgo.jwt.base.support;

import com.asvgo.jwt.base.JWTTokenUtilBase;
import com.asvgo.jwt.base.JWTUserFactoryBase;
import com.asvgo.jwt.exception.TokenAbsentException;
import com.google.common.collect.Maps;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

@RestController
public class AuthController{
    @Value("${jwt.header}")
    private String tokenHeader;
    @Value("${jwt.tokenHead}")
    private String tokenHead;

    @Autowired
    private AuthService authService;
    @Autowired
    private JWTTokenUtilBase jwtTokenUtil;
    @Autowired
    private JWTUserFactoryBase jwtUserFactory;

    @PostMapping(value = "${jwt.route.authentication.path}")
    public ResponseEntity<?> createAuthenticationToken(
            @RequestBody LoginUser user) throws AuthenticationException{
        final String token = authService.login(user.getUsername(), user.getPassword());
        Map map = Maps.newHashMap();
        map.put("status", "success");
        return new ResponseEntity(map, authHeaders(token),HttpStatus.OK);
    }

    @GetMapping(value = "${jwt.route.authentication.refresh}")
    public ResponseEntity<?> refreshAndGetAuthenticationToken(
            HttpServletRequest request) throws AuthenticationException{
        String authHeader = request.getHeader(tokenHeader);
        if(authHeader==null){
            throw new TokenAbsentException();
        }
        String token = authHeader.substring(tokenHead.length());
        String refreshedToken = authService.refresh(token);
        if(refreshedToken == null) {
            return new ResponseEntity(null,authHeaders(""),HttpStatus.UNAUTHORIZED);
        } else {
            Map map = Maps.newHashMap();
            map.put("status", "success");
            return new ResponseEntity(map, authHeaders(refreshedToken),HttpStatus.OK);
        }
    }

    @PostMapping("${jwt.route.authentication.logout}")
    public ResponseEntity logout(HttpServletRequest req, HttpServletResponse res){
        Map map = Maps.newHashMap();
        map.put("status", "success");
        map.put("msg", "Logged out Successfully.");
        return new ResponseEntity(map,authHeaders(""),HttpStatus.OK);
    }

    private HttpHeaders authHeaders(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS,tokenHeader);
        headers.add(tokenHeader,tokenHead.concat(token));
        return headers;
    }

    @GetMapping("${jwt.route.authentication.user}")
    public ResponseEntity user(HttpServletRequest req) {
        String authHeader = req.getHeader(tokenHeader);
        if(authHeader==null){
            throw new TokenAbsentException();
        }
        String token = authHeader.substring(tokenHead.length());
        Object jwtUser = jwtUserFactory.create(jwtTokenUtil.getAuthentication(token));

        Map<String,Object> map = Maps.newHashMap();
        map.put("status", "success");
        map.put("data", jwtUser);
        return new ResponseEntity(map, HttpStatus.OK);
    }
}

@Data
class LoginUser {
    private String username;
    private String password;
}