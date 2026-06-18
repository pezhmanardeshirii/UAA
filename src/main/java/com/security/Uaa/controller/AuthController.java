package com.security.Uaa.controller;

import com.security.Uaa.config.PasswordConfig;
import com.security.Uaa.dto.LoginRequest;
import com.security.Uaa.dto.LogoutRequest;
import com.security.Uaa.dto.RefreshTokenRequest;
import com.security.Uaa.model.AuthResponse;
import com.security.Uaa.model.RefreshToken;
import com.security.Uaa.model.User;
import com.security.Uaa.repository.UserRepository;
import com.security.Uaa.security.JwtService;
import com.security.Uaa.security.RefreshTokenService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final RefreshTokenService refreshTokenService;
    private UserRepository userRepository;
    private PasswordConfig passwordConfig;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    public AuthController(RefreshTokenService refreshTokenService, UserRepository userRepository,
                          PasswordConfig passwordConfig,
                          JwtService jwtService, AuthenticationManager authenticationManager) {
        this.refreshTokenService = refreshTokenService;
        this.userRepository = userRepository;
        this.passwordConfig = passwordConfig;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/register")
    public User register(@RequestBody User user) {
        user.setPassword(passwordConfig.passwordEncoder().encode(user.getPassword()));
        return userRepository.save(user);
    }

    @PostMapping("/login")
    public AuthResponse login(@RequestBody LoginRequest loginRequest) {

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        User user = userRepository.findByUsername(loginRequest.getUsername())
                .orElseThrow();


        String accessToken =
                jwtService.generateToken(user);

        String refreshToken =
                refreshTokenService.createRefreshToken(user);

        return new AuthResponse(
                accessToken,
                refreshToken
        );


    }

    @PostMapping("/refresh")
    public AuthResponse refresh (@RequestBody RefreshTokenRequest request){
        RefreshToken refreshToken =
                refreshTokenService.validateRefreshToken(request.getRefreshToken());

        User user = refreshToken.getUser();

        String accessToken = jwtService.generateToken(user);

        return new AuthResponse(
                accessToken,
                refreshToken.getToken()
        );

    }

    @PostMapping("/logout")
    public String logout(@RequestBody LogoutRequest request) {
        refreshTokenService.logOut(request.getRefreshToken());
        return "LogOut successful";
    }


    @GetMapping("/hello")
    public String hello() {
        return "HELLO SECURED API";
    }

}
