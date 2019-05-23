package com.asvgo.jwt.base;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static com.asvgo.jwt.base.support.JWTUtils.role2SimpleGrantedAuthority;


/**
 * @author Kelvin范显
 * @createDate 2018年01月04日
 */
public abstract class JWTTokenUtilBase<T extends JWTUserBase> implements Serializable {
    private final long serialVersionUID = -3301605591108950415L;

    static final String CLAIM_KEY_ID = "sub";
    static final String CLAIM_KEY_CREATED = "created";
    static final String CLAIM_KEY_USERNAME = "name";
    static final String CLAIM_KEY_ROLES = "roles";

    @Value("${jwt.secret}")
    String secret;

    @Value("${jwt.expiration}")
    Long expiration;

    @Value("${jwt.header}")
    protected
    String tokenHeader;

    @Value("${jwt.tokenHead}")
    protected
    String tokenHead;

    public String generateToken(T jwtUser) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_KEY_ID, jwtUser.getId());
        claims.put(CLAIM_KEY_USERNAME, jwtUser.getUsername());
        claims.put(CLAIM_KEY_CREATED, new Date());
        claims.put(CLAIM_KEY_ROLES, jwtUser.getRoles());
        appendSelfClaims(claims, jwtUser); //钩子方法 补充自定义payload
        return generateToken(claims);
    }

    /**
     * 钩子方法，追加项目自定义的payload
     * @param claims
     * @param jwtUser
     */
    protected abstract void appendSelfClaims(Map<String, Object> claims, T jwtUser);

    public Boolean canTokenBeRefreshed(String token, Date lastPasswordReset) {
        final Date created = getCreatedDateFromToken(token);
        return !isCreatedBeforeLastPasswordReset(created, lastPasswordReset)
                && !isTokenExpired(token);
    }
    public String refreshToken(String token) {
        String refreshedToken;
        try {
            final Claims claims = getClaimsFromToken(token);
            claims.put(CLAIM_KEY_CREATED, new Date());
            refreshedToken = generateToken(claims);
        } catch (Exception e) {
            refreshedToken = null;
        }
        return refreshedToken;
    }
    public Boolean validateToken(String token, T user) {
        final String username = getUserIdFromToken(token);
        final Date created = getCreatedDateFromToken(token);
        return (
                username.equals(user.getUsername())
                        && !isTokenExpired(token)
                        && !isCreatedBeforeLastPasswordReset(created, user.getLastPasswordResetDate()));
    }

    ///getters
    /**
     * 通过token获取认证，这里的权限是SimpleGrantedAuthority
     * 如果是其他权限，复写该方法
     * @param token
     * @return
     */
    public Authentication getAuthentication(String token) {
        String userId = getPayloadFromToken(token, Claims::getSubject);
        List<String> rolesList = getPayloadFromToken(token, CLAIM_KEY_ROLES);
        return new UsernamePasswordAuthenticationToken(userId, null, role2SimpleGrantedAuthority(rolesList));
    }
    public String getUserIdFromToken(String token) {
        return getPayloadFromToken(token,Claims::getSubject);
    }
    public String gerUserNameFromToken(String token) {
        return getPayloadFromToken(token, CLAIM_KEY_USERNAME);
    }
    public Date getCreatedDateFromToken(String token) {
        Long timeStamp = getPayloadFromToken(token,CLAIM_KEY_CREATED);
        return new Date(timeStamp);
    }
    public List<String> getRolesFromToken(String token) {
        return getPayloadFromToken(token,CLAIM_KEY_ROLES);
    }
    public Date getExpirationDateFromToken(String token) {
        return getPayloadFromToken(token,Claims::getExpiration);
    }

    ///generic getters
    public <T> T getPayloadFromToken(String token, String key) {
        T t;
        try {
            final Claims claims = getClaimsFromToken(token);
            t = (T) claims.get(key);
        } catch (Exception e) {
            t = null;
        }
        return t;
    }
    public <T> T getPayloadFromToken(String token, Function<Claims,T> getClaim) {
        T t;
        try {
            final Claims claims = getClaimsFromToken(token);
            t = getClaim.apply(claims);
        } catch (Exception e) {
            t = null;
        }
        return t;
    }

    ///self helper
    private Claims getClaimsFromToken(String token) {
        Claims claims;
        claims = Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
        return claims;
    }
    private String generateToken(Map<String, Object> claims) {
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(generateExpirationDate())
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }
    private Date generateExpirationDate() {
        return new Date(System.currentTimeMillis() + expiration * 1000);
    }
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }
    private Boolean isCreatedBeforeLastPasswordReset(Date created, Date lastPasswordReset) {
        return (lastPasswordReset != null && created.before(lastPasswordReset));
    }
}
