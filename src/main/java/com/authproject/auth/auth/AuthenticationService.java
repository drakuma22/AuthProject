package com.authproject.auth.auth;


import com.authproject.auth.auth.viewModel.AuthenticationRefresh;
import com.authproject.auth.auth.viewModel.AuthenticationRequest;
import com.authproject.auth.auth.viewModel.AuthenticationResponse;
import com.authproject.auth.config.JwtService;
import com.authproject.auth.user.User;
import com.authproject.auth.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public ResponseEntity<?> register(User user) {
        try {
            String hashedPassword = passwordEncoder.encode(user.getPassword());
            user.setPassword(hashedPassword);
            repository.save(user);
            return new ResponseEntity<>("Utente registrato con successo", HttpStatus.OK);
        }catch (Exception e){
            return new ResponseEntity<>("Errore durante la registrazione dell'utente", HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    public ResponseEntity<?> login(AuthenticationRequest request) {
        try{
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        }catch (BadCredentialsException e){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        final User user = repository.findByEmail(request.getEmail()).orElseThrow();
        final String token = jwtService.generateToken(user);
        final String refreshToken = jwtService.createRefreshToken(user);
        return ResponseEntity.ok(new AuthenticationResponse(token, refreshToken));
    }

    public ResponseEntity<?> refreshAuth(AuthenticationRefresh authenticationRefresh){
        try{
            final String newAccessToken = jwtService.refreshToken(authenticationRefresh.getRefreshToken());
            final String email = jwtService.extractUsername(newAccessToken);
            final long expirationDate = jwtService.extractExpiration(newAccessToken).getTime();

            return ResponseEntity.ok(new AuthenticationResponse(newAccessToken, authenticationRefresh.getRefreshToken()));
        }catch (Exception e){
            return new ResponseEntity<>("Invalid Refresh Token", HttpStatus.UNAUTHORIZED);
        }
    }


}
