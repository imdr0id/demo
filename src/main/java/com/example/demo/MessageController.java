package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MessageController {


    @Autowired
    AuthenticationManager authenticationManager;


    @PostMapping("/login")
    public String login(@RequestBody UsernamePwd usernamePwd) {
        Authentication as=    authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(usernamePwd.getUsername(),usernamePwd.getPwd()));

        return "Hello Spring Security "+as.isAuthenticated();
    }


    @GetMapping("/hello")
    public String hello() {
        return "Hello Spring Security";
    }
}
