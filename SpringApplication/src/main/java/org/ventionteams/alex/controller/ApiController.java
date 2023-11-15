package org.ventionteams.alex.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ApiController {

    @Value("${app.value}")
    private String appValue;

    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok(String.format("Service #%s is ok.", appValue));
    }

}
