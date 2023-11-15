package com.ventionteams.alex.config;

public enum Scope {
    READ("ROLE_USER"),
    TOKEN("ROLE_ADMIN");

    private final String role;

    Scope(String role) {
        this.role = role;
    }

    public String getRole(){
        return role;
    }
}
