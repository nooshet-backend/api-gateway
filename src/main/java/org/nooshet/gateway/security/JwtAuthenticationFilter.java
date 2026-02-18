package org.nooshet.gateway.security;

import org.nooshet.gateway.service.JwtProcessor;
import org.nooshet.gateway.web.support.RequestUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationFilter implements WebFilter {

    private final JwtProcessor jwtProcessor;

    public JwtAuthenticationFilter(JwtProcessor jwtProcessor) {
        this.jwtProcessor = jwtProcessor;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String token = extractToken(exchange);
        
        if (token != null && !token.isEmpty()) {
            return jwtProcessor.validateTokenForGateway(token)
                    .flatMap(validation -> {
                        if (validation.valid) {
                            Authentication auth = createAuthentication(validation);
                            ServerWebExchange mutatedExchange = exchange.mutate()
                                    .request(exchange.getRequest().mutate()
                                            .header("X-User-Id", validation.userId != null ? validation.userId.toString() : "")
                                            .header("X-User-Email", validation.email != null ? validation.email : "")
                                            .header("X-User-Roles", validation.roles != null ? String.join(",", validation.roles) : "")
                                            .build())
                                    .build();
                            
                            return chain.filter(mutatedExchange)
                                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
                        }
                        return chain.filter(exchange);
                    });
        }

        return chain.filter(exchange);
    }

    private String extractToken(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null; // Or check query param if supported
    }

    private Authentication createAuthentication(JwtProcessor.TokenValidationResult validation) {
        List<SimpleGrantedAuthority> authorities = validation.roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());

        // Principal can be userId or email
        return new UsernamePasswordAuthenticationToken(validation.userId, null, authorities);
    }
}
