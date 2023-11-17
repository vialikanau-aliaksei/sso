package com.ventionteams.alex.gateway.config;

public enum LocationPattern {
    API("/api/**", "/oauth2/authorization/gateway-user"),
    TOKEN("/token/**", "/oauth2/authorization/gateway-admin");

    private final String pattern;
    private final String location;

    LocationPattern(String pattern, String location) {
        this.pattern = pattern;
        this.location = location;
    }

    public String getPattern() {
        return pattern;
    }

    public String getLocation() {
        return location;
    }
}
