package org.ventionteams.alex.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${spring.security.oauth2.resourceserver.opaque-token.introspection-uri}")
    private String introspectionUrl;

    @Value("${spring.security.oauth2.resourceserver.opaque-token.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.resourceserver.opaque-token.client-secret}")
    private String clientSecret;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/api/**").hasAuthority("SCOPE_read")
                        .requestMatchers("/token/**").hasAuthority("SCOPE_token")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(configurer -> configurer.opaqueToken(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    public OpaqueTokenIntrospector customSpringOpaqueTokenIntrospector(ObjectMapper objectMapper) {
        OpaqueTokenIntrospector introspector = new SpringOpaqueTokenIntrospector(introspectionUrl, clientId, clientSecret);
        return new CustomSpringOpaqueTokenIntrospector(introspector, objectMapper);
    }
}
