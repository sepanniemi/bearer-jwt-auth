package com.sepanniemi.iam.bearerjwtauth;

import lombok.Builder;
import org.springframework.security.core.GrantedAuthority;

@Builder
public class Scope implements GrantedAuthority {
    private final String scope;

    @Override
    public String getAuthority() {
        return scope;
    }
}
