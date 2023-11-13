package com.authproject.auth.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('USER')")
public class AdminController {
    @GetMapping
    ResponseEntity<?> restAdminController(){
        return ResponseEntity.ok("It's ok");
    }
}
