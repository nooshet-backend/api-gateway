package org.nooshet.gateway.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.security.Key;
import java.util.List;
import java.util.UUID;

@Component
public class JwtProcessor {

    @Value("${JWT_SECRET:your-jwt-secret-change-in-production}")
    private String secretKey;

    private final ReactiveRedisTemplate<String, String> redisTemplate;

    private Key signingKey;
    private io.jsonwebtoken.JwtParser jwtParser;

    public JwtProcessor(ReactiveRedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @PostConstruct
    public void init() {
        if (secretKey == null || secretKey.length() < 32) {
             // Fallback for dev if secret is too short or missing, to avoid startup error
             secretKey = "default-secret-key-must-be-very-long-to-be-secure-enough-for-hs256";
        }
        this.signingKey = Keys.hmacShaKeyFor(secretKey.getBytes());
        this.jwtParser = Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build();
    }

    public String generateJti() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    public Mono<TokenValidationResult> validateTokenForGateway(String token) {
        return validateTokenInternal(token, false);
    }

    public Mono<TokenValidationResult> validateToken(String token) {
        return validateTokenInternal(token, true);
    }

    private Mono<TokenValidationResult> validateTokenInternal(String token, boolean checkBlacklist) {
        if (token == null || token.isEmpty()) {
            return Mono.just(new TokenValidationResult(false, null, null, null, null));
        }

        try {
            Claims claims = jwtParser.parseClaimsJws(token).getBody();

            if (claims.getExpiration() != null && claims.getExpiration().before(new java.util.Date())) {
                return Mono.just(new TokenValidationResult(false, null, null, null, null));
            }

            // IAM service puts userId in 'sub' claim (as string), not email
            String subjectStr = claims.getSubject();
            Long parsedUserId = null;
            if (subjectStr != null && !subjectStr.isEmpty()) {
                try {
                    parsedUserId = Long.parseLong(subjectStr);
                } catch (NumberFormatException e) {
                    // It might be email or UUID in other systems, but we try Long first as per fitnest
                    parsedUserId = claims.get("userId", Long.class);
                }
            }
            final Long userId = parsedUserId;
            
            final String email = claims.get("email", String.class);
            final String jti = claims.get("jti", String.class);
            @SuppressWarnings("unchecked")
            final List<String> roles = claims.get("roles", List.class);

            if (checkBlacklist && jti != null) {
                String blacklistKey = "blacklist:jti:" + jti;
                return redisTemplate.hasKey(blacklistKey)
                        .map(isBlacklisted -> {
                            if (Boolean.TRUE.equals(isBlacklisted)) {
                                return new TokenValidationResult(false, null, null, null, null);
                            }
                            return new TokenValidationResult(true, email, userId, roles, jti);
                        });
            }

            return Mono.just(new TokenValidationResult(true, email, userId, roles, jti));

        } catch (Exception e) {
            return Mono.just(new TokenValidationResult(false, null, null, null, null));
        }
    }

    public boolean isAdminRoute(String path) {
        return path.startsWith("/api/v1/admin/");
    }

    public static class TokenValidationResult {
        public final boolean valid;
        public final String email;
        public final Long userId;
        public final List<String> roles;
        public final String jti;

        public TokenValidationResult(boolean valid, String email, Long userId, List<String> roles, String jti) {
            this.valid = valid;
            this.email = email;
            this.userId = userId;
            this.roles = roles;
            this.jti = jti;
        }
    }
}
