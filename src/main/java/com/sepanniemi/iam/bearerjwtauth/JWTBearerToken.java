package com.sepanniemi.iam.bearerjwtauth;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;


@Getter
public class JWTBearerToken extends AbstractAuthenticationToken {

    private final JWTUser user;
    private final String encodedJwt;

    public JWTBearerToken(JWTUser user, String encodedJwt) {
        super(user.getAuthorities());
        setAuthenticated(true);
        this.user = user;
        this.encodedJwt = encodedJwt;
    }

    @Override
    public Object getCredentials() {
        return encodedJwt;
    }

    @Override
    public Object getPrincipal() {
        return user;
    }
}
