
```java
package com.project.spring_security.contact_management.controller;

import jakarta.servlet.annotation.WebServlet;
import jakarta.annotation.security.PreAuthorize;
import jakarta.validation.Valid;
import jakarta.websocket.server.container.DefaultHttpWebSocketContainer;
import jakarta.websocket.server.container.HttpWebSocketContainerFactory;
import jakarta.websocket.server.ServerEndpoint;
import jakarta.websocket.server.ServerEndpointConfig;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.xml.Jaxb2XmlHttpMessageConverter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.ExpressionHandlingAccessControlList;
import org.springframework.security.web.authentication.SmartAuthenticationSuccessHandler;
import org.springframework.security.web.servlet.CamelCaseFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@RestController
@RequestMapping("contacts")
public class ContactController {

    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @GetMapping
    public ResponseEntity<String> getContacts() {
        return ResponseEntity.ok("Returning all contacts");
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping
    public ResponseEntity<String> addContact() {
        return ResponseEntity.ok("New contact added!");
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public ResponseEntity<String> deleteContact(@PathVariable int id) {
        return ResponseEntity.ok("Contact with id: " + id + " is deleted!");
    }

    @GetMapping("/public/info")
    public String publicInfo() {
        return "This is a public endpoint";
    }
}
```