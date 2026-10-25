package com.sentinelmesh.controlplane.security;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

class ApiKeyAuthFilterRegressionTest {

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void validDetectorKeyAuthenticatesAsDetectionEngine() throws Exception {
        var filter = new ApiKeyAuthFilter(
            "detection-engine:detector-test-secret," +
            "security-automation:automation-test-secret"
        );
        var request = request("/incidents", "detector-test-secret");
        var response = new MockHttpServletResponse();
        var chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertNotNull(chain.getRequest(), "valid request must continue");
        assertEquals(
            "detection-engine",
            SecurityContextHolder.getContext().getAuthentication().getName()
        );
    }

    @Test
    void missingKeyIsRejected() throws Exception {
        var filter = new ApiKeyAuthFilter(
            "detection-engine:detector-test-secret"
        );
        var response = new MockHttpServletResponse();
        var chain = new MockFilterChain();

        filter.doFilter(request("/incidents", null), response, chain);

        assertEquals(401, response.getStatus());
        assertNull(chain.getRequest(), "unauthenticated request must stop");
    }

    @Test
    void invalidKeyIsRejected() throws Exception {
        var filter = new ApiKeyAuthFilter(
            "detection-engine:detector-test-secret"
        );
        var response = new MockHttpServletResponse();
        var chain = new MockFilterChain();

        filter.doFilter(request("/incidents", "wrong-test-secret"),
                        response, chain);

        assertEquals(401, response.getStatus());
        assertNull(chain.getRequest(), "invalid key must not continue");
    }

    @Test
    void healthEndpointDoesNotRequireApiKey() throws Exception {
        var filter = new ApiKeyAuthFilter(
            "detection-engine:detector-test-secret"
        );
        var response = new MockHttpServletResponse();
        var chain = new MockFilterChain();

        filter.doFilter(request("/actuator/health", null),
                        response, chain);

        assertNotNull(chain.getRequest());
        assertEquals(200, response.getStatus());
    }

    @Test
    void duplicateKeysForDifferentCallersAreRejected() {
        assertThrows(
            IllegalStateException.class,
            () -> new ApiKeyAuthFilter(
                "detection-engine:duplicate-secret," +
                "security-automation:duplicate-secret"
            )
        );
    }

    @Test
    void composeAllowlistOverridesApplicationDefault() throws Exception {
        String yaml;
        try (var input = new ClassPathResource("application.yml")
                .getInputStream()) {
            yaml = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }

        var pattern = Pattern.compile(
            "(?m)^[\\t ]*api-keys:[\\t ]*\"([^\"]+)\"[\\t ]*$"
        );
        var matcher = pattern.matcher(yaml);

        assertTrue(matcher.find(), "application.yml must define api-keys");

        String propertyValue = matcher.group(1);
        assertTrue(
            propertyValue.startsWith("${SENTINELMESH_API_KEYS:"),
            "application.yml must prioritize the Compose allowlist"
        );

        String composeAllowlist =
            "detection-engine:configured-test-key," +
            "security-automation:configured-automation-key";

        var environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(
            new MapPropertySource(
                "test-compose-environment",
                Map.of("SENTINELMESH_API_KEYS", composeAllowlist)
            )
        );

        assertEquals(
            composeAllowlist,
            environment.resolveRequiredPlaceholders(propertyValue)
        );
    }

    private static MockHttpServletRequest request(
            String path, String apiKey) {
        var request = new MockHttpServletRequest("GET", path);
        request.setRequestURI(path);
        if (apiKey != null) {
            request.addHeader(ApiKeyAuthFilter.HEADER, apiKey);
        }
        return request;
    }
}
