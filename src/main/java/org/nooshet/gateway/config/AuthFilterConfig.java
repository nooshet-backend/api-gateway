package org.nooshet.gateway.config;

import org.nooshet.gateway.service.BlockManager;
import org.nooshet.gateway.service.JwtProcessor;
import org.nooshet.gateway.service.RateLimiter;

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

            // Public paths and Swagger are handled by SecurityWebFilterChain permitAll()
            // but we still want rate limiting for them.
            
            String method = sanitizedExchange.getRequest().getMethod().name();
            String clientIP = RequestUtils.extractClientIP(sanitizedExchange.getRequest());

            return rateLimiter.checkRateLimit(clientIP, path, method)
                    .flatMap(result -> {
                        if (result == -1) {
                            return ResponseUtils.respondWithTooManyRequests(sanitizedExchange);
                        }
                        return chain.filter(sanitizedExchange);
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



    @Bean
    public GlobalFilter securityHeadersFilter() {
        return (exchange, chain) -> {
            SecurityHeaders.addSecurityHeaders(exchange.getResponse());
            return chain.filter(exchange);
        };
    }

}
