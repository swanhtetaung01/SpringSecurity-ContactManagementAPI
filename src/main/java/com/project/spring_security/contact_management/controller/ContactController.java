package com.project.spring_security.contact_management.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/contacts")
public class ContactController {

    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @GetMapping
    public String getContacts() {
        return "Returning all contacts";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping
    public String addContact() {
        return "New contact added!";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public String deleteContact(@PathVariable int id) {
        return "Contact with id: " + id + "is deleted!";
    }

    @GetMapping("/public/info")
    public String publicInfo() {
        return "This is a public endpoint";
    }
}
