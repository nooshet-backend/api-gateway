package org.nooshet.gateway.web.support;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;

public class RequestUtils {

    private RequestUtils() {
    }

    public static String extractClientIP(ServerHttpRequest request) {
        String xForwardedFor = request.getHeaders().getFirst("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIP = request.getHeaders().getFirst("X-Real-IP");
        if (xRealIP != null && !xRealIP.isEmpty()) {
            return xRealIP;
        }

        if (request.getRemoteAddress() != null && request.getRemoteAddress().getAddress() != null) {
            return request.getRemoteAddress().getAddress().getHostAddress();
        }
        return "unknown";
    }

    public static String extractToken(ServerWebExchange exchange) {
        var accessTokenCookie = exchange.getRequest().getCookies().getFirst("accessToken");
        if (accessTokenCookie != null && !accessTokenCookie.getValue().isEmpty()) {
            return accessTokenCookie.getValue();
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }

        return null;
    }

    public static boolean isStateChangingMethod(String method) {
        return "POST".equals(method) || "PUT".equals(method) || "DELETE".equals(method) || "PATCH".equals(method);
    }

    public static String extractCsrfTokenFromCookies(ServerHttpRequest request) {
        var csrfCookie = request.getCookies().getFirst("csrfTokenHttpOnly");
        return csrfCookie != null ? csrfCookie.getValue() : null;
    }
}
