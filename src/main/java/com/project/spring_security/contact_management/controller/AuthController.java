
```

package com.project.spring_security.contact_management.controller;

import com.project.spring_security.contact_management.security.LoginRequest;
import com.project.spring_security.contact_management.security.LoginResponse;
import com.project.spring_security.contact_management.security.jwt.JwtUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import jakarta.annotation.security.permitall;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * AuthController handles user authentication.
 */
@RestController
@ApplicationScoped
public class AuthController {

    @Inject
    private JwtUtils jwtUtils;

    @Inject
    private AuthenticationManager authenticationManager;

    /**
     * Authenticates the user with the provided credentials.
     *
     * @param loginRequest The request object containing user credentials.
     * @return A ResponseEntity with a LoginResponse object on success,
     * or an HttpStatus.NOT_FOUND on failure.
     */
    @PostMapping("/signin")
    public ResponseEntity<LoginResponse> authenticateUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication;
        try {
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(), loginRequest.getPassword()
                            )
                    );
        } catch (AuthenticationException exception) {
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad credentials");
            map.put("status", false);
            return new ResponseEntity<>(map, HttpStatus.NOT_FOUND);
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String jwtToken = jwtUtils.generateJwtTokenFromUsername(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        LoginResponse response = new LoginResponse(jwtToken, roles, userDetails.getUsername());

        return ResponseEntity.ok(response);
    }
}

```