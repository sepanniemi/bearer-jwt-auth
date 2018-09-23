package com.sepanniemi.iam.bearerjwtauth;

import lombok.SneakyThrows;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

@Configuration
@EnableWebFluxSecurity
@EnableConfigurationProperties(SecurityProperties.class)
public class SecurityConfig {

    @Bean
    @SneakyThrows
    RSAPublicKey tokenVerificationKey(SecurityProperties securityProperties) {

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(securityProperties.getPublicKeyFile().getInputStream());
        return RSAPublicKey.class.cast(cert.getPublicKey());
    }

    @Bean
    JwtBearerTokenAuthenticationManager authenticationManager(RSAPublicKey publicKey) {
        return new JwtBearerTokenAuthenticationManager(new NimbusReactiveJwtDecoder(publicKey));
    }

    @Bean
    SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http,
            SecurityProperties securityProperties) {
        http
                .authorizeExchange()
                .pathMatchers("/**").hasAuthority("global")
                .anyExchange().authenticated()
                .and()
                .oauth2ResourceServer()
                .jwt()
                .authenticationManager(authenticationManager(tokenVerificationKey(securityProperties)));
        return http.build();
    }
}
