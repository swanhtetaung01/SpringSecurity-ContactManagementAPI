
package com.project.spring_security.contact_management.security;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class LoginVerifier {

    @AuthenticationPrincipal
    private final LoginRequest loginRequest;

    public LoginVerifier(LoginRequest loginRequest) {
        this.loginRequest = loginRequest;
    }

    public boolean verify(String externalUsername) {
        return externalUsername.equals(loginRequest.getUsername());
    }
}

package com.project.spring_security.contact_management.controller;

import com.project.spring_security.contact_management.security.LoginRequest;
import com.project.spring_security.contact_management.security.LoginVerifier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Validated
@Controller
@RequestMapping("/api/contacts")
public class ContactsController {

    private final ContactService contactService;
    private final LoginVerifier loginVerifier;

    @Autowired
    public ContactsController(ContactService contactService, LoginVerifier loginVerifier) {
        this.contactService = contactService;
        this.loginVerifier = loginVerifier;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        if (loginVerifier.verify("testUser")) {
            return ResponseEntity.ok().build();
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    @GetMapping("/contacts")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<List<Contact>> getContacts(@AuthenticationPrincipal LoginRequest loginRequest) {
        return ResponseEntity.ok(contactService.getAllContacts());
    }
}