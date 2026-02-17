package org.nooshet.gateway.service;

import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Component
public class BlockManager {

    private final ReactiveRedisTemplate<String, String> redisTemplate;

    private static final int USER_BLOCK_THRESHOLD = 5;
    private static final int IP_BLOCK_THRESHOLD = 50;
    private static final Duration USER_BLOCK_DURATION = Duration.ofMinutes(15);
    private static final Duration IP_BLOCK_DURATION = Duration.ofHours(1);

    public BlockManager(ReactiveRedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public Mono<Boolean> isBlocked(String clientIP, String userEmail) {
        if (userEmail != null && !userEmail.isEmpty()) {
            String userBlockKey = "blocked:user:" + userEmail;
            return redisTemplate.hasKey(userBlockKey)
                    .flatMap(userBlocked -> {
                        if (userBlocked) {
                            return Mono.just(true);
                        }
                        String ipBlockKey = "blocked:ip:" + clientIP;
                        return redisTemplate.hasKey(ipBlockKey);
                    });
        }

        String ipBlockKey = "blocked:ip:" + clientIP;
        return redisTemplate.hasKey(ipBlockKey);
    }

    public Mono<Long> recordFailedAttempt(String clientIP, String userEmail) {
        if (userEmail != null && !userEmail.isEmpty()) {
            return recordFailedAttempt(userEmail, USER_BLOCK_THRESHOLD, USER_BLOCK_DURATION, "user");
        }

        return recordFailedAttempt(clientIP, IP_BLOCK_THRESHOLD, IP_BLOCK_DURATION, "ip");
    }

    private Mono<Long> recordFailedAttempt(String identifier, int threshold, Duration blockDuration, String type) {
        String attemptsKey = "failed_attempts:" + type + ":" + identifier;
        String blockKey = "blocked:" + type + ":" + identifier;

        return redisTemplate.opsForValue().increment(attemptsKey)
                .flatMap(attempts -> {
                    if (attempts == 1) {
                        return redisTemplate.expire(attemptsKey, blockDuration)
                                .thenReturn(attempts);
                    }
                    return Mono.just(attempts);
                })
                .flatMap(attempts -> {
                    if (attempts >= threshold) {
                        return redisTemplate.opsForValue().set(blockKey, "1")
                                .then(redisTemplate.expire(blockKey, blockDuration))
                                .then(redisTemplate.delete(attemptsKey))
                                .thenReturn(attempts);
                    }
                    return Mono.just(attempts);
                });
    }
}
