package org.ventionteams.alex.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.introspector.introspection-uri}")
    private String introspectionUri;
    @Value("${spring.security.oauth2.resourceserver.opaquetoken.introspector.client-id}")
    private String introspectorClientId;
    @Value("${spring.security.oauth2.resourceserver.opaquetoken.introspector.client-secret}")
    private String introspectorClientSecret;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/api/**").hasAuthority("SCOPE_read")
                        .requestMatchers("/token/**").hasAuthority("SCOPE_token")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(configurer -> configurer.opaqueToken(token -> token.introspector(introspector())));
        return http.build();
    }

    private OpaqueTokenIntrospector introspector() {
        return new SpringOpaqueTokenIntrospector(introspectionUri, introspectorClientId, introspectorClientSecret);
    }
}
