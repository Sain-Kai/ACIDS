package com.sentinelmesh.controlplane.client;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Authenticated host-agent addressing. In production the registry is supplied
 * by configuration/service-discovery, e.g. host-a=https://10.0.0.10:9090.
 * Hostname fallback is disabled by default for production so DNS cannot be
 * silently redirected to an unintended privileged endpoint.
 */
@Component
public class HostRegistry {
    private final Map<String,String> endpoints = new LinkedHashMap<>();
    private final boolean allowHostnameFallback;
    private final int defaultPort;

    public HostRegistry(@Value("${sentinelmesh.host-registry:}") String csv,
                        @Value("${sentinelmesh.host-agent.port:9090}") int defaultPort,
                        @Value("${sentinelmesh.host-registry-allow-hostname-fallback:false}") boolean allowHostnameFallback) {
        this.defaultPort = defaultPort;
        this.allowHostnameFallback = allowHostnameFallback;
        if (csv != null) {
            for (String item : csv.split(",")) {
                String[] parts = item.trim().split("=",2);
                if (parts.length == 2 && !parts[0].isBlank() && !parts[1].isBlank()) {
                    endpoints.put(parts[0].trim(), normalize(parts[1].trim()));
                }
            }
        }
    }

    public String endpointFor(String hostname) {
        if (hostname == null || hostname.isBlank()) return null;
        String known = endpoints.get(hostname);
        if (known != null) return known;
        if (!allowHostnameFallback) return null;
        return normalize("http://" + hostname + ":" + defaultPort);
    }

    public List<String> hosts() { return List.copyOf(endpoints.keySet()); }

    private static String normalize(String endpoint) {
        return endpoint.replaceAll("/+$", "");
    }
}
