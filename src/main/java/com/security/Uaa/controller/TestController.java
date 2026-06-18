package com.security.Uaa.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/print")
public class TestController {

    @GetMapping("/hello")
    public String hello() {
        return "HELLO SECURED API";
    }

    @GetMapping("/admin")
    public String admin(){
        return "ADMIN SECURED API";
    }
}
