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
        if (path.startsWith("/api/v1/goals/images/")) {
            return false;
        }
        return path.startsWith("/api/v1/me") ||
               path.startsWith("/api/v1/internal/") ||
               path.startsWith("/api/v1/media/upload") ||
               path.startsWith("/api/v1/media/delete") ||
               path.startsWith("/api/v1/media/move") ||
               path.startsWith("/api/v1/marketplace/") ||
               path.startsWith("/api/v1/gyms/") ||
               path.startsWith("/api/v1/checkout/") ||
               AUTH_REQUIRED_PATHS.contains(path) ||
               requiresAuthForContent(path);

    }

    public static boolean isAdminRoute(String path) {
        return false;
    }

    public static boolean startsWithApiV1(String path) {
        return path.startsWith("/api/v1/");
    }
}
