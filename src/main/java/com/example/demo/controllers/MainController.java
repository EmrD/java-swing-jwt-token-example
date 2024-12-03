package com.example.demo.controllers;

import java.util.UUID;
import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@RestController
public class MainController {
    // Güçlü bir anahtar oluşturuyoruz
    private static final SecretKey SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    @GetMapping("/api/v1/auth/createToken")
    public String createToken(@RequestParam String username) {
        String id = UUID.randomUUID().toString();
        String token = createJWT(id, "api-auth", username, 3600000);
        return token;
    }

    public static String createJWT(String id, String issuer, String subject, long ttlMillis) { 
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);

        JwtBuilder builder = Jwts.builder()
                .setId(id)
                .setIssuedAt(now)
                .setSubject(subject)
                .setIssuer(issuer)
                .signWith(SECRET_KEY, signatureAlgorithm);

        if (ttlMillis > 0) {
            long expMillis = nowMillis + ttlMillis;
            Date exp = new Date(expMillis);
            builder.setExpiration(exp);
        }

        return builder.compact();
    }

    @GetMapping("/api/v1/auth/checkToken")
    public boolean checkToken(@RequestParam String token) {
        try {
            decodeJWT(token);
            return true;
        } 
        catch (Exception e) {
            return false;
        }
    }

    public static Claims decodeJWT(String jwt) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(jwt)
                .getBody();
        return claims;
    }
}
