package com.security.Uaa.security;

import com.security.Uaa.model.RefreshToken;
import com.security.Uaa.model.User;
import com.security.Uaa.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    public String createRefreshToken(User user) {

        String token = UUID.randomUUID().toString();

        RefreshToken refreshToken = new RefreshToken();

        refreshToken.setToken(token);

        refreshToken.setUser(user);

        refreshToken.setExpiryDate(
                new Date(
                        System.currentTimeMillis()
                                + 7L * 24 * 60 * 60 * 1000
                )
        );

        refreshTokenRepository.save(refreshToken);

        return token;
    }

    public RefreshToken validateRefreshToken(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token).orElseThrow();

        if (refreshToken.getExpiryDate().before(new Date()))
            throw new RuntimeException("Refresh token expired");

        return refreshToken;
    }
    public void logOut(String token) {
        refreshTokenRepository.findByToken(token)
                .ifPresent(refreshTokenRepository::delete);
    }
}
