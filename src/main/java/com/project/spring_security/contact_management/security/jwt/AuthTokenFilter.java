
package com.project.spring_security.contact_management.security.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.expression.SecurityExpressionHandlerAdapter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtAuthenticationFilterConfig jwtAuthenticationFilterConfig;

    @Autowired
    private JwtUtils jwtUtils;

    private static final Logger logger = LoggerFactory.getLogger("JwtAuthenticationFilter.class");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (!jwtUtils.isValidToken(jwtAuthenticationFilterConfig.getTokenHeader(), request)) {
            logger.debug("Rejected JWT received");
            response.setStatus(401);
            response.getWriter().write("Rejected JWT received");
            return;
        }
        // Allow the request to propagate through the filter chain.
        filterChain.doFilter(request, response);
    }

    @PostConstruct
    public void init() {
        JwtAuthenticationFilterConfig config = jwtAuthenticationFilterConfig.getFilterConfig();
        String[] allowedRoles = config.getAllowedRoles();
        if (Arrays.asList(allowedRoles).contains(SecurityContextHolder.getContext().getAuthentication().getAuthorities().toString())) {
            logger.debug("Allowed roles for current filter: {}", Arrays.toString(allowedRoles));
        } else {
            logger.debug("Rejected roles for current filter: {}", Arrays.toString(allowedRoles));
            response.setStatus(403);
            response.getWriter().write("Access denied");
        }
    }

}

package com.project.spring_security.contact_management.security.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Component
public class JwtAuthorizedRequestsFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    private static final Logger logger = LoggerFactory.getLogger("JwtAuthorizedRequestsFilter.class");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !jwtUtils.isJwtAuthenticated(authentication)) {
            logger.debug("Not JWT authenticated");
            response.setStatus(401);
            response.getWriter().write("Not authenticated");
            return;
        }
        filterChain.doFilter(request, response);
    }

}

package com.project.spring_security.contact_management.security.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@Component
public class JwtTokenUtil extends org.springframework.security.core.context.SecurityContextHolder {

    @Autowired
    private JwtUtils jwtUtils;

    @Override
    public void clearAndResetSecurity() {
        SecurityContextHolder.clearContext();
        super.clearAndResetSecurity();
    }

    public String getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null
                ? jwtUtils.extractUserFromToken(authentication.getPrincipal()) : null;
    }

    public void removeCurrentUser() {
        SecurityContextHolder.getContext().setAuthentication(null);
    }

    public void logOut() {
        removeCurrentUser();
        clearAndResetSecurity();
        jwtUtils.invalidateJwtToken(SecurityContextHolder.getContext().getAuthentication().getPrincipal());
    }

}

package com.project.spring_security.contact_management.security.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    private static final Logger logger = LoggerFactory.getLogger("JwtRequestFilter.class");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (jwtUtils.isJwtRequest(request)) {
            String jwtToken = jwtUtils.generateJwtTokenFromHeader(request);
            if (jwtToken != null) {
                String username = jwtUtils.generateUsernameFromJwtToken(jwtToken);
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                logger.debug("Roles from JWT: {}", userDetails.getAuthorities());
            }
        }
        filterChain.doFilter(request, response);
    }

}

package com.project.spring_security.contact_management.security.jwt;

import lombok. attemp.com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.MongoId;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document
public class JwtUser {

    @Id
    @MongoId
    private String id;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private Date expiryDate;

    private String username;

    private String password;

    private String token;

    private String role;

}

package com.project.spring_security.contact_management.service;

import com.project.spring_security.contact_management.security.jwt.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;

@Service
public class AuthService {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Transactional
    public Authentication authenticate(String username, String password) {
        return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                username, password));
    }

    public void createUser(String username, String password) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (userDetails == null) {
            // create user
        }
    }

    public void createRole(String role) {
        // create role
    }

}

package com.project.spring_security.contact_management.controller;

import com.project.spring_security.contact_management.security.jwt.JwtTokenUtil;
import com.project.spring_security.contact_management.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;

@RestController
@RequestMapping("/api")
public class ContactController {

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @PostMapping("/login")
    public String login(@RequestBody String credentials) {
        String[] creds = credentials.split(":");
        String username = creds[0];
        String password = creds[1];
        Authentication authentication = authService.authenticate(username, password);
        SecurityContextHolder.getContext().setAuthentication