package org.ventionteams.alex.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

public class CustomSpringOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private final OpaqueTokenIntrospector opaqueTokenIntrospector;

    private final ObjectMapper objectMapper;
    public CustomSpringOpaqueTokenIntrospector(OpaqueTokenIntrospector opaqueTokenIntrospector, ObjectMapper objectMapper) {
        this.opaqueTokenIntrospector = opaqueTokenIntrospector;
        this.objectMapper = objectMapper;
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        OAuth2AuthenticatedPrincipal authenticatedPrincipal = opaqueTokenIntrospector.introspect(token);
        try {
            System.out.println(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(authenticatedPrincipal));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        return authenticatedPrincipal;
    }
}
