package org.nooshet.gateway.security.support;

import org.nooshet.gateway.web.support.RequestUtils;
import org.nooshet.gateway.web.support.ResponseUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class CsrfValidator {

    private CsrfValidator() {
    }

    public static Mono<Void> validateCsrfToken(ServerWebExchange exchange, String path, String method) {
        try {
            String userAgent = exchange.getRequest().getHeaders().getFirst("User-Agent");
            if (isMobileApp(userAgent)) {
                return Mono.empty();
            }

            boolean isCsrfExemptedPath = PathValidator.isCsrfExempted(path);
            boolean isAdminPath = path.startsWith("/api/v1/admin/");
            String cookieCsrfToken = RequestUtils.extractCsrfTokenFromCookies(exchange.getRequest());

            if (cookieCsrfToken != null &&
                (RequestUtils.isStateChangingMethod(method) ||
                 isAdminPath) &&
                PathValidator.startsWithApiV1(path) &&
                !isCsrfExemptedPath) {

                String requestCsrfToken = exchange.getRequest().getHeaders().getFirst("X-CSRF-Token");

                if (requestCsrfToken == null || !requestCsrfToken.equals(cookieCsrfToken)) {
                    return ResponseUtils.respondWithForbidden(exchange.getResponse());
                }
            }

            return Mono.empty();
        } catch (Exception e) {
            return Mono.empty();
        }
    }

    private static boolean isMobileApp(String userAgent) {
        if (userAgent == null) {
            return false;
        }
        
        String lowerUserAgent = userAgent.toLowerCase();
        return lowerUserAgent.contains("nooshet-mobile") ||
               lowerUserAgent.contains("okhttp") ||
               lowerUserAgent.contains("retrofit") ||
               lowerUserAgent.contains("android") ||
               lowerUserAgent.contains("ios") ||
               lowerUserAgent.contains("mobile");
    }
}
