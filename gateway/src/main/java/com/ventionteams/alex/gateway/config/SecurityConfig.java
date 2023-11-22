package com.ventionteams.alex.gateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.GatewayFilterSpec;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
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
    @Profile("auth")
    public SecurityWebFilterChain configureAuthSecurity(ServerHttpSecurity http) {
        http
                .authorizeExchange(c -> c.pathMatchers("/login").permitAll())
                .authorizeExchange(c -> c.anyExchange().authenticated())
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(authenticationEntryPoint())
                )
                .oauth2Login(withDefaults());
        return http.build();
    }

    @Bean
    @Profile("keycloak")
    public SecurityWebFilterChain configureKeycloakSecurity(ServerHttpSecurity http) {
        http
                .authorizeExchange(c -> c.pathMatchers("/login").permitAll())
                .authorizeExchange(c -> c.anyExchange().authenticated())
                .oauth2Login(withDefaults());
        return http.build();
    }

    private ServerAuthenticationEntryPoint authenticationEntryPoint(){
        Map<String, String> patterns = Arrays.stream(LocationPattern.values())
                .collect(Collectors.toMap(LocationPattern::getPattern, LocationPattern::getLocation));
        return new CustomAuthenticationEntryPoint(patterns);
    }

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("token", r -> r.path("/token/**")
                        .filters(GatewayFilterSpec::tokenRelay)
                        .uri("lb://resourceapp")).build();
    }
}
