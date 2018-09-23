package com.sepanniemi.iam.bearerjwtauth;

import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class AuthenticatedController {

    @GetMapping("/auth-echo")
    public Mono<JWTBearerToken> echo() {
        return ReactiveSecurityContextHolder
                .getContext()
                .map(c -> JWTBearerToken.class.cast(c.getAuthentication()));
    }
}
