package com.security.Uaa.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Setter
@Getter
public class AuthResponse {
    private String accessToken;
    private String refreshToken;


}
