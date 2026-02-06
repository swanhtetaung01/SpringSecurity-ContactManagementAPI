package com.project.spring_security.contact_management;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/contacts")
public class ContactController {

    @GetMapping
    public String getContacts() {
        return "Returning all contacts";
    }

    @PostMapping
    public String addContact() {
        return "New contact added!";
    }

    @DeleteMapping("/{id}")
    public String deleteContact(@PathVariable int id) {
        return "Contact with id: " + id + "is deleted!";
    }

    @GetMapping("/public/info")
    public String publicInfo() {
        return "This is a public endpoint";
    }
}
