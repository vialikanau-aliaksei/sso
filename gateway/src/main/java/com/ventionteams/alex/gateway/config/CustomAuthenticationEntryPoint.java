package com.ventionteams.alex.gateway.config;

import org.springframework.http.HttpMethod;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.savedrequest.ServerRequestCache;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Map;
import java.util.stream.Collectors;

public class CustomAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    private final Map<ServerWebExchangeMatcher, String> matchers;

    public CustomAuthenticationEntryPoint(Map<String, String> patterns) {
        matchers = patterns.entrySet().stream()
                .collect(Collectors.toMap(
                        e -> ServerWebExchangeMatchers.pathMatchers(HttpMethod.GET, e.getKey()),
                        Map.Entry::getValue
                ));
    }

    private ServerRequestCache requestCache = new WebSessionServerRequestCache();
    private ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();
    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        final String location = matchers.entrySet().stream()
                .filter(e -> {
                    ServerWebExchangeMatcher.MatchResult matchResult;
                    try {
                        matchResult = e.getKey().matches(exchange).toFuture().get();
                    } catch (Exception exc) {
                        System.out.println(exc.getMessage());
                        throw new RuntimeException(exc);
                    }
                    return matchResult.isMatch();
                })
                .map(Map.Entry::getValue).findFirst().orElse("/login");
        return this.requestCache.saveRequest(exchange)
                .then(this.redirectStrategy.sendRedirect(exchange, URI.create(location)));
    }
}
