package com.project.spring_security.contact_management.security.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

@Component
public class JwtUtils {
    
    private static final Logger logger = LoggerFactory.getLogger("JwtUtils.class");

    @Value("${spring.app.jwtSecretKey}")
    private String jwtSecretKey;

    public String generateToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization Header: {}", bearerToken);
        if(bearerToken != null && bearerToken.startsWith("Bearer "))
            return bearerToken.substring(7);
        return null;
    }

    public String generateUsernameFromJwtToken(String jwtToken) {
        return Jwts.parser()
                .verifyWith(key())
                .build().parseSignedClaims(jwtToken)
                .getPayload().getSubject();
    }

    public SecretKey key(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecretKey));
    }
}
