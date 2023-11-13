package com.authproject.auth.auth;


import com.authproject.auth.auth.viewModel.AuthenticationRefresh;
import com.authproject.auth.auth.viewModel.AuthenticationRequest;
import com.authproject.auth.config.JwtService;
import com.authproject.auth.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    private final JwtService jwtService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthenticationRequest login){
        return authenticationService.login(login);
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user){
        return ResponseEntity.ok(authenticationService.register(user));
    }

    @PostMapping("/refreshAuth")
    public ResponseEntity<?> refreshAuth(@RequestBody AuthenticationRefresh authRefresh){
        return ResponseEntity.ok(authenticationService.refreshAuth(authRefresh));
    }


}
