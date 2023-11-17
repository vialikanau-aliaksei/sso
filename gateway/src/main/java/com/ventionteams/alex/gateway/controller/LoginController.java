package com.ventionteams.alex.gateway.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import reactor.core.publisher.Mono;

@Controller
public class LoginController {

    @GetMapping("/login")
    public Mono<String> getLogin(){
        return Mono.just("login");
    }
}
