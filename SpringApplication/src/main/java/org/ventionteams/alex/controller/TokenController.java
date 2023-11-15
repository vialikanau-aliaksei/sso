package org.ventionteams.alex.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/token")
public class TokenController {

    @GetMapping("/info")
    public ResponseEntity<BearerTokenAuthentication> foo(BearerTokenAuthentication authentication) {
        return ResponseEntity.ok(authentication);
    }

}
