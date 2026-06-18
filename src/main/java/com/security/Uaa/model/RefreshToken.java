package com.security.Uaa.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.OneToOne;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Setter
@Getter
@Entity
public class RefreshToken {
    @Id
    @GeneratedValue
    private Long id;

    private String token;

    private Date expiryDate;

    @OneToOne
    private User user;
}
