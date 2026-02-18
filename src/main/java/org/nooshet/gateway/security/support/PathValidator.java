package org.nooshet.gateway.security.support;

import org.springframework.util.AntPathMatcher;
import java.util.List;

public class PathValidator {

    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

    private static final List<String> PUBLIC_ENDPOINTS = List.of(
        "/api/v1/auth/login",
        "/api/v1/auth/register/**",
        "/api/v1/auth/verify-otp",
        "/api/v1/auth/password-reset/**",
        "/api/v1/auth/refresh",
        "/v3/api-docs/**",
        "/swagger-ui/**",
        "/swagger-ui.html",
        "/actuator/**",
        "/webjars/**"
    );

    private PathValidator() {
    }

    public static boolean isPublic(String path) {
        return PUBLIC_ENDPOINTS.stream()
                .anyMatch(pattern -> PATH_MATCHER.match(pattern, path));
    }

    public static boolean requiresAuth(String path) {
        return !isPublic(path);
    }

    // Retaining strictly for compatibility if referenced elsewhere, but usage should migrate to isPublic/requiresAuth
    public static boolean isCsrfExempted(String path) {
        // For simplicity and robustness, improved logic:
        // CSRF usually optional for public GETs, but essential for state-changing.
        // If public, we might skip CSRF or handle it. 
        // For now, let's keep it aligning with 'public' for the register endpoints logic implicitly.
        return false; 
    }

    public static boolean startsWithApiV1(String path) {
        return path.startsWith("/api/v1/");
    }
}
