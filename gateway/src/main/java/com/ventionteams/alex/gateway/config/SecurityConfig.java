package com.ventionteams.alex.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;

import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain configureApiSecurity(ServerHttpSecurity http) {
        http
                .authorizeExchange(c -> c.pathMatchers("/login").permitAll())
                .authorizeExchange(c -> c.anyExchange().authenticated())
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(authenticationEntryPoint())
                )
                .oauth2Login(withDefaults());
        return http.build();
    }

    private ServerAuthenticationEntryPoint authenticationEntryPoint(){
        Map<String, String> patterns = Arrays.stream(LocationPattern.values())
                .collect(Collectors.toMap(LocationPattern::getPattern, LocationPattern::getLocation));
        return new CustomAuthenticationEntryPoint(patterns);
    }
}
