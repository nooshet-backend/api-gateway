package org.nooshet.gateway.config;

import org.nooshet.gateway.service.BlockManager;
import org.nooshet.gateway.service.JwtProcessor;
import org.nooshet.gateway.service.RateLimiter;
import org.nooshet.gateway.security.support.CsrfValidator;
import org.nooshet.gateway.security.support.PathValidator;
import org.nooshet.gateway.security.support.SecurityHeaders;
import org.nooshet.gateway.web.support.RequestUtils;
import org.nooshet.gateway.web.support.ResponseUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Configuration
public class AuthFilterConfig {

    @Autowired
    private RateLimiter rateLimiter;

    @Autowired
    private BlockManager blockManager;

    @Autowired
    private JwtProcessor jwtProcessor;

    @Bean
    public GlobalFilter authFilter() {
        return (exchange, chain) -> {
            ServerWebExchange sanitizedExchange = sanitizeHeaders(exchange);
            String path = sanitizedExchange.getRequest().getPath().value();

            if (path.contains("/internal/")) {
                return ResponseUtils.respondWithForbidden(sanitizedExchange.getResponse());
            }

            if (path.startsWith("/v3/api-docs") || path.startsWith("/swagger-ui") || path.startsWith("/swagger")) {
                return chain.filter(sanitizedExchange);
            }

            String method = sanitizedExchange.getRequest().getMethod().name();
            String clientIP = RequestUtils.extractClientIP(sanitizedExchange.getRequest());

            return rateLimiter.checkRateLimit(clientIP, path, method)
                    .flatMap(result -> {
                        if (result == -1) {
                            return ResponseUtils.respondWithTooManyRequests(sanitizedExchange);
                        }

                        return proceedWithAuth(sanitizedExchange, chain, path, method, clientIP);
                    });
        };
    }

    private ServerWebExchange sanitizeHeaders(ServerWebExchange exchange) {
        return exchange.mutate()
                .request(exchange.getRequest().mutate()
                        .headers(h -> {
                            h.remove("X-User-Id");
                            h.remove("X-User-Email");
                            h.remove("X-User-Roles");
                        })
                        .build())
                .build();
    }

    private Mono<Void> proceedWithAuth(ServerWebExchange exchange, GatewayFilterChain chain, String path, String method, String clientIP) {
        String token = RequestUtils.extractToken(exchange);
        boolean requiresAuth = PathValidator.requiresAuth(path);

        if (requiresAuth && (token == null || token.isEmpty())) {
            return handleAuthFailure(exchange, clientIP, path);
        }

        if (token != null && !token.isEmpty()) {
            return jwtProcessor.validateTokenForGateway(token)
                    .flatMap(validation -> handleTokenValidation(exchange, chain, validation, requiresAuth, clientIP, path, token));
        }

        return chain.filter(exchange);
    }

    private Mono<Void> handleAuthFailure(ServerWebExchange exchange, String clientIP, String path) {
        Mono<Void> recordMono = path.equals("/api/v1/auth/verify-otp") ?
            Mono.empty() : blockManager.recordFailedAttempt(clientIP, null).then();
        return recordMono.then(ResponseUtils.respondWithUnauthorized(exchange.getResponse()));
    }

    private Mono<Void> handleTokenValidation(ServerWebExchange exchange, GatewayFilterChain chain,
                                           JwtProcessor.TokenValidationResult validation, boolean requiresAuth,
                                           String clientIP, String path, String token) {
        // Bypass block checks for public registration and verification endpoints
        if (!requiresAuth) {
            return chain.filter(exchange);
        }
        if (!validation.valid) {
            if (requiresAuth) {
                return handleAuthFailure(exchange, clientIP, path);
            } else {
                return chain.filter(exchange);
            }
        }

        return blockManager.isBlocked(clientIP, validation.email)
                .flatMap(blocked -> {
                    if (blocked) {
                        return ResponseUtils.respondWithForbidden(exchange.getResponse());
                    }

                    ServerWebExchange modifiedExchange = addUserHeaders(exchange, token, validation);
                    return chain.filter(modifiedExchange);
                });
    }

    private ServerWebExchange addUserHeaders(ServerWebExchange exchange, String token, JwtProcessor.TokenValidationResult validation) {
        return exchange.mutate()
                .request(exchange.getRequest().mutate()
                        .header("Authorization", "Bearer " + token)
                        .header("X-User-Email", validation.email)
                        .header("X-User-Id", validation.userId != null ? validation.userId.toString() : "")
                        .header("X-User-Roles", validation.roles != null ? String.join(",", validation.roles) : "")
                        .build())
                .build();
    }


    @Bean
    public GlobalFilter securityHeadersFilter() {
        return (exchange, chain) -> {
            SecurityHeaders.addSecurityHeaders(exchange.getResponse());

            String path = exchange.getRequest().getPath().value();
            String method = exchange.getRequest().getMethod().name();

            return CsrfValidator.validateCsrfToken(exchange, path, method)
                    .then(chain.filter(exchange));
        };
    }

}
