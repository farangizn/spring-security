package org.example.oauth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
public class JwtUtils {

    public String extractUsernameFromToken(String jwtToken) {
        Claims claims = Jwts.parser()
                .verifyWith(signKey())
                .build()
                .parseSignedClaims(jwtToken)
                .getPayload();
        return claims.getSubject();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()));
    }

    public SecretKey signKey() {
        byte[] bytes = Decoders.BASE64.decode("l4gKDJ79v10j8tGHOZ+nQAz/i5c/Hc4NktN2P7C6ZP0=");
        return Keys.hmacShaKeyFor(bytes);
    }

    public String generateToken(String username) {
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                .signWith(signKey())
                .compact();
    }
}
