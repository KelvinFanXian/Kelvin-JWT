package com.asvgo.jwt.base;

import lombok.Data;

import javax.validation.constraints.NotNull;
import java.util.Date;
import java.util.List;

@Data
public abstract class JWTUserBase {
    Object id;
    String username;
    String nickname;
    String password;
    List<String> roles;
    @NotNull
    Date lastPasswordResetDate;
}
