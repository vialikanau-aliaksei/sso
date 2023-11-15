package com.ventionteams.alex.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;

public class RolesFilter extends OncePerRequestFilter {

    private static final String SPRING_SECURITY_SAVED_REQUEST = "SPRING_SECURITY_SAVED_REQUEST";
    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";
    private static final String SCOPE = "scope";
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public RolesFilter(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        HttpSession session = request.getSession(false);
        Collection<? extends GrantedAuthority> authorities = getUserAuthorities(request);
        allow: if (session != null && !authorities.isEmpty()) {

            List<String> userScopes = extractUserScopes(authorities);

            Object rawAttribute = session.getAttribute(SPRING_SECURITY_SAVED_REQUEST);
            if (!userScopes.isEmpty() && rawAttribute instanceof DefaultSavedRequest defaultSavedRequest) {

                String[] clientScopesValues = defaultSavedRequest.getParameterValues(SCOPE);
                if (clientScopesValues != null && clientScopesValues.length > 0) {
                    String clientScopes = clientScopesValues[0].toUpperCase();
                    for (String userScope: userScopes) {
                        if (clientScopes.contains(userScope)){
                            break allow;
                        }
                    }
                    response.reset();
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.setHeader("Location", request.getRequestURL().toString());
                    return;
                }
            }
        }
        filterChain.doFilter(request, response);
    }

    private List<String> extractUserScopes(Collection<? extends GrantedAuthority> authorities) {
        List<String> roles = new ArrayList<>();
        for (Scope scope: Scope.values()) {
            for (GrantedAuthority authority : authorities) {
                if (authority.getAuthority().equals(scope.getRole())) {
                    roles.add(scope.name());
                }
            }
        }
        return roles;
    }

    private  Collection<? extends GrantedAuthority> getUserAuthorities(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();

        if (parameterMap.containsKey(USERNAME)) {
            String[] usernames = parameterMap.get(USERNAME);
            String[] passwords = parameterMap.get(PASSWORD);
            UserDetails userDetails = userDetailsService.loadUserByUsername(usernames[0]);
            if (passwordEncoder.matches(passwords[0], userDetails.getPassword())) {
                return userDetails.getAuthorities();
            }
        }
        return Collections.emptyList();
    }
}
