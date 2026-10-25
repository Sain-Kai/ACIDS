package com.sentinelmesh.controlplane.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Minimal API-key auth: every request except /actuator/health must carry
 * a valid key in X-SentinelMesh-Api-Key, checked against the configured
 * caller-name -> key map. Deliberately simple -- this is a
 * service-to-service API (detection-engine and llm-orchestration are the
 * only two callers in this deployment), not a public-facing one, so a
 * shared-secret header is proportionate. A real deployment fronting this
 * with real human users/roles should replace this with OAuth2/mTLS, not
 * extend this filter.
 *
 * If sentinelmesh.security.api-keys is empty or malformed, the resulting
 * key map is empty -- every request gets 401. Fails closed, not open.
 */
@Component
public class ApiKeyAuthFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-SentinelMesh-Api-Key";

    private final Map<String, String> keyToCallerName;

    public ApiKeyAuthFilter(@Value("${sentinelmesh.security.api-keys}") String apiKeysCsv) {
        // Format: "callerName:key,callerName2:key2"
        Map<String, String> tmp = new LinkedHashMap<>();
        Arrays.stream(apiKeysCsv == null ? new String[0] : apiKeysCsv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> s.split(":", 2))
                .filter(parts -> parts.length == 2 && !parts[0].isBlank() && !parts[1].isBlank())
                .forEach(parts -> {
                    if (tmp.put(parts[1], parts[0]) != null) {
                        throw new IllegalStateException("duplicate SentinelMesh API key configured for multiple callers");
                    }
                });
        this.keyToCallerName = Map.copyOf(tmp);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (request.getRequestURI().startsWith("/actuator/health") || request.getRequestURI().equals("/actuator/prometheus")) {
            chain.doFilter(request, response);
            return;
        }

        String key = request.getHeader(HEADER);
        String caller = null;
        if (key != null) {
            for (var entry : keyToCallerName.entrySet()) {
                if (MessageDigest.isEqual(key.getBytes(StandardCharsets.UTF_8), entry.getKey().getBytes(StandardCharsets.UTF_8))) {
                    caller = entry.getValue();
                    break;
                }
            }
        }
        if (caller == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"missing or invalid " + HEADER + "\"}");
            return;
        }

        var auth = new UsernamePasswordAuthenticationToken(caller, null, Collections.emptyList());
        SecurityContextHolder.getContext().setAuthentication(auth);
        chain.doFilter(request, response);
    }
}
