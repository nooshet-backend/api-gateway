package org.nooshet.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Component
@ConfigurationProperties(prefix = "nooshet.rate-limit")
public class RateLimitConfig {

    private Map<String, Integer> limits = new HashMap<>();

    public RateLimitConfig() {
        // Auth-specific limits (per minute)
        limits.put("auth.login.post", 5);
        limits.put("auth.verify-otp.post", 5);
        limits.put("auth.request-otp.post", 3);
        limits.put("auth.send-reset-password-link.post", 2);
        limits.put("auth.reset-password.post", 5);

        // Generic limits
        limits.put("general.write", 60);
        limits.put("general.read", 300);
    }

    public int getLimit(String key) {
        return limits.getOrDefault(key, 300);
    }

    public String getReadCategory(String path) {
        if (path.startsWith("/api/v1/auth/")) {
            return "AUTH_GET";
        } else if (path.startsWith("/api/v1/me/")) {
            return "ME_GET";
        } else {
            return "GENERAL_GET";
        }
    }

    public String getRateLimitKey(String path, String method) {
        boolean isRead = "GET".equals(method);
        boolean isWrite = Arrays.asList("POST", "PUT", "DELETE", "PATCH").contains(method);

        // Auth logic
        if (path.startsWith("/api/v1/auth/login") && isWrite) {
            return "auth.login.post";
        } else if (path.startsWith("/api/v1/auth/otp/send") && isWrite) {
            return "auth.request-otp.post";
        } else if ((path.startsWith("/api/v1/auth/otp/verify")
                || path.startsWith("/api/v1/auth/forgot-password/verify-otp")) && isWrite) {
            return "auth.verify-otp.post";
        } else if (path.equals("/api/v1/auth/forgot-password") && isWrite) {
            return "auth.send-reset-password-link.post";
        } else if (path.equals("/api/v1/auth/reset-password") && isWrite) {
            return "auth.reset-password.post";
        }

        if (isWrite) {
            return "general.write";
        } else if (isRead) {
            return "general.read";
        }

        return "general.read";
    }

    public Map<String, Integer> getLimits() {
        return limits;
    }

    public void setLimits(Map<String, Integer> limits) {
        this.limits = limits;
    }
}
