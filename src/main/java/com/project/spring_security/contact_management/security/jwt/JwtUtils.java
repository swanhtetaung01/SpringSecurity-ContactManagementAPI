
```

```java
package com.project.spring_security.contact_management.security.jwt;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import jakarta.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtils {

    @Value("${spring.security.jwt.expiration}")
    private int jwtExpirationMs;

    private static final Logger logger = LoggerFactory.getLogger("JwtUtils.class");

    @Value("${spring.security.jwt.secretKey}")
    private String jwtSecretKey;

    @Deprecated(forRemoval = true)
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
                .expiration(new Date(new Date().getTime() + jwtExpirationMs))
                .signWith(key())
                .compact();
    }

    public SecretKey key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecretKey));
    }

    public boolean validateJwtToken(String jwtToken) throws JwtException {
        try {
            Jwts.parser().verifyWith(key()).build().parseSignedClaims(jwtToken);
            return true;
        } catch (ExpiredJwtException e) {
            logger.error("Expired JWT token: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("Unsupported JWT token: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}
```