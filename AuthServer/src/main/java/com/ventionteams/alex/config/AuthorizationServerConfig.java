package com.ventionteams.alex.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.GenericFilterBean;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    @Value("${spring.security.oauth2.opaquetoken.user.client-id}")
    private String userClientId;
    @Value("${spring.security.oauth2.opaquetoken.user.client-secret}")
    private String userClientSecret;
    @Value("${spring.security.oauth2.opaquetoken.admin.client-id}")
    private String adminClientId;
    @Value("${spring.security.oauth2.opaquetoken.admin.client-secret}")
    private String adminClientSecret;
    @Value("${spring.security.oauth2.opaquetoken.introspector.client-id}")
    private String introspectorClientId;
    @Value("${spring.security.oauth2.opaquetoken.introspector.client-secret}")
    private String introspectorClientSecret;
    @Value("${spring.security.oauth2.authorizationserver.issuer-url}")
    private String issuerUrl;
    @Value("${spring.security.oauth2.authorizationserver.introspection-endpoint}")
    private String introspectionEndpoint;

    @Bean
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());
        http.oauth2ResourceServer(configurer -> configurer.opaqueToken(Customizer.withDefaults()));
        return http.formLogin(Customizer.withDefaults()).build();
    }

    @Bean
    public OpaqueTokenIntrospector opaqueTokenIntrospector() {
        return new SpringOpaqueTokenIntrospector(introspectionEndpoint, userClientId, userClientSecret);
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient introspectorClient = getRegisteredIntrospectorClient();
        RegisteredClient userClient = getRegisteredUserClient();
        RegisteredClient adminClient = getRegisteredAdminClient();
        return new InMemoryRegisteredClientRepository(introspectorClient, adminClient, userClient);
    }

    private RegisteredClient getRegisteredUserClient() {
        return RegisteredClient.withId("userId")
                .clientName("user")
                .clientId(userClientId)
                .clientSecret("{noop}" + userClientSecret)
                .redirectUri("http://localhost:8080/login/oauth2/code/gateway-user")
                .scope(OidcScopes.OPENID).scope("read")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .accessTokenTimeToLive(Duration.of(30, ChronoUnit.MINUTES))
                        .refreshTokenTimeToLive(Duration.of(120, ChronoUnit.MINUTES))
                        .reuseRefreshTokens(false)
                        .authorizationCodeTimeToLive(Duration.of(30, ChronoUnit.SECONDS))
                        .build()).build();
    }

    private RegisteredClient getRegisteredAdminClient() {
        return RegisteredClient.withId("adminId")
                .clientName("admin")
                .clientId(adminClientId)
                .clientSecret("{noop}" + adminClientSecret)
                .redirectUri("http://localhost:8080/login/oauth2/code/gateway-admin")
                .scope(OidcScopes.OPENID).scope("token")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .accessTokenTimeToLive(Duration.of(30, ChronoUnit.MINUTES))
                        .refreshTokenTimeToLive(Duration.of(120, ChronoUnit.MINUTES))
                        .reuseRefreshTokens(false)
                        .authorizationCodeTimeToLive(Duration.of(30, ChronoUnit.SECONDS))
                        .build()).build();
    }

    private RegisteredClient getRegisteredIntrospectorClient() {
        return RegisteredClient.withId("introspectorId")
                .clientName("introspector")
                .clientId(introspectorClientId)
                .clientSecret("{noop}" + introspectorClientSecret)
                .redirectUri("http://localhost:8080/login/oauth2/code/gateway-admin")
                .scope(OidcScopes.OPENID)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .accessTokenTimeToLive(Duration.of(30, ChronoUnit.MINUTES))
                        .refreshTokenTimeToLive(Duration.of(120, ChronoUnit.MINUTES))
                        .reuseRefreshTokens(false)
                        .authorizationCodeTimeToLive(Duration.of(30, ChronoUnit.SECONDS))
                        .build()).build();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(issuerUrl)
                .tokenIntrospectionEndpoint(introspectionEndpoint)
                .build();
    }
}