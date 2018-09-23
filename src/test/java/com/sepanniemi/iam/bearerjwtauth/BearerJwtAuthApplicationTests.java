package com.sepanniemi.iam.bearerjwtauth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.restassured.RestAssured;
import lombok.SneakyThrows;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.junit4.SpringRunner;

import java.security.Key;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Date;

import static io.restassured.RestAssured.given;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class BearerJwtAuthApplicationTests {


    @Autowired
    public void setup(@LocalServerPort int port) {
        RestAssured.port = port;
    }

    @Test
    public void contextLoads() {
    }

    @Test
    @SneakyThrows
    public void testGetAuth() {

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(new ClassPathResource("jwtauth.jks").getInputStream(), "passwd".toCharArray());

        Key key = keyStore.getKey("jwtkey", "passwd".toCharArray());

        JWSSigner signer = new RSASSASigner(RSAPrivateKey.class.cast(key));

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet
                .Builder()
                .subject("whoami")
                .expirationTime(new Date(Instant.now().plusSeconds(180).toEpochMilli()))
                .audience("auht-echo")
                .claim("scope", "global").build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), jwtClaimsSet);

        jwt.sign(signer);

        String token = jwt.serialize();

        given()
                .auth().oauth2(token)
                    .log().all()
                .get("/auth-echo")
                .then()
                    .log().all()
                    .statusCode(200);

    }

}
