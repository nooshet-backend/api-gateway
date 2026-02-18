package org.nooshet.gateway.security.support;

import java.util.Set;

public class PathValidator {

    private static final Set<String> CSRF_EXEMPTED_PATHS = Set.of();

    private static final Set<String> AUTH_REQUIRED_PATHS = Set.of();

    public static boolean requiresAuthForContent(String path) {
        return false;
    }

    private PathValidator() {
    }

    public static boolean isCsrfExempted(String path) {
        return CSRF_EXEMPTED_PATHS.contains(path);
    }

    public static boolean requiresAuth(String path) {
        // Registration and verification endpoints (public)
        if (path.equals("/api/v1/auth/login") ||
            path.equals("/api/v1/auth/register/courier") ||
            path.equals("/api/v1/auth/register/user") ||
            path.equals("/api/v1/auth/register/chef") ||
            path.equals("/api/v1/auth/register/courier/complete") ||
            path.equals("/api/v1/auth/register/user/complete") ||
            path.equals("/api/v1/auth/register/chef/complete") ||
            path.equals("/api/v1/auth/verify-otp") ||
            path.equals("/api/v1/auth/password-reset/request") ||
            path.equals("/api/v1/auth/password-reset/verify") ||
            path.equals("/api/v1/auth/password-reset/complete") ||
            path.equals("/api/v1/auth/refresh") ||
            path.startsWith("/api/v1/auth/register/") ||
            path.equals("/api/v1/auth/refresh") ||
            path.startsWith("/api/v1/auth/register/") ||
            path.startsWith("/api/v1/auth/password-reset/")) {
            return false;
        }
        
        return path.startsWith("/api/v1/me") ||
               path.startsWith("/api/v1/profiles/") || 
               path.startsWith("/api/v1/internal/") ||
               path.startsWith("/api/v1/admin/") ||
               AUTH_REQUIRED_PATHS.contains(path) ||
               requiresAuthForContent(path);

    }

    public static boolean isAdminRoute(String path) {
        // Simple check, refine as needed based on exact admin paths
        return path.startsWith("/api/v1/admin/");
    }

    public static boolean startsWithApiV1(String path) {
        return path.startsWith("/api/v1/");
    }
}
