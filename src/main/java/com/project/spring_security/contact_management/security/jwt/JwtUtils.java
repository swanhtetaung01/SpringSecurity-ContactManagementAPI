package com.project.spring_security.contact_management.security.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtils {

    @Value("${spring.app.jwtExpiration}")
    private int jwtExpiraionMs;

    private static final Logger logger = LoggerFactory.getLogger("JwtUtils.class");

    @Value("${spring.app.jwtSecretKey}")
    private String jwtSecretKey;

    public String generateJwtTokenFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization Header: {}", bearerToken);
        if (bearerToken != null && bearerToken.startsWith("Bearer "))
            return bearerToken.substring(7);
        return null;
    }

    public String generateUsernameFromJwtToken(String jwtToken) {
        return Jwts.parser()
                .verifyWith(key())
                .build().parseSignedClaims(jwtToken)
                .getPayload().getSubject();
    }

    public String generateJwtTokenFromUsername(UserDetails userDetails) {
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + jwtExpiraionMs))
                .signWith(key())
                .compact();
    }

    public SecretKey key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecretKey));
    }

    public boolean validateJwtToken(String jwtToken) {
        try{
            System.out.println("Validating token");
            Jwts.parser().verifyWith(key()).build().parseSignedClaims(jwtToken);
            System.out.println("Validated");
            return true;
        }catch(MalformedJwtException e){
            logger.error("Invalid JWT token: {}", e.getMessage());
        }catch(ExpiredJwtException e) {
            logger.error("Expired JWT token: {}", e.getMessage());
        }catch(UnsupportedJwtException e){
            logger.error("Unsupported JWT token: {}", e.getMessage());
        }catch(IllegalArgumentException e){
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}
