package com.asvgo.jwt.exception;

/**
 * @author Kelvin范显
 * @createDate 2017年10月26日
 */
public class TokenAbsentException extends RuntimeException {
    public TokenAbsentException() {
        super("The token is absent.");
    }
}
