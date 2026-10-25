package com.sentinelmesh.controlplane.client;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Uses a real JDK HttpServer as a fake host-agent rather than mocking
 * Spring's RestClient -- RestClient's fluent builder chain is awkward to
 * mock meaningfully, and a real (if tiny) server exercises the actual
 * wire contract: headers sent, status codes handled, JSON shapes parsed.
 */
class HostAgentClientTest {

    private HttpServer server;
    private int port;
    private static final String API_KEY = "test-agent-key";

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        port = server.getAddress().getPort();
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    private HostAgentClient client() {
        return new HostAgentClient(port, API_KEY);
    }

    @Test
    void sendsApiKeyHeaderOnEveryCall() throws IOException {
        AtomicReference<String> seenHeader = new AtomicReference<>();
        server.createContext("/v1/network/isolate", exchange -> {
            seenHeader.set(exchange.getRequestHeaders().getFirst("X-SentinelMesh-Api-Key"));
            respondJson(exchange, 200, "{\"isolated\":true}");
        });
        server.start();

        assertTrue(client().isolate("localhost", "10.0.0.5"));
        assertEquals(API_KEY, seenHeader.get());
    }

    @Test
    void killParsesResultCounts() throws IOException {
        server.createContext("/v1/kill", exchange ->
                respondJson(exchange, 200, "{\"attempted\":2,\"killed\":1,\"skipped\":1}"));
        server.start();

        HostAgentClient.KillResult r = client().kill("localhost",
                List.of(new HostAgentClient.KillTarget(123, "/tmp/x")));

        assertEquals(2, r.attempted());
        assertEquals(1, r.killed());
        assertEquals(1, r.skipped());
    }

    @Test
    void killWithNoTargetsSkipsTheCallEntirely() throws IOException {
        AtomicBoolean called = new AtomicBoolean(false);
        server.createContext("/v1/kill", exchange -> {
            called.set(true);
            respondJson(exchange, 200, "{\"attempted\":0,\"killed\":0,\"skipped\":0}");
        });
        server.start();

        HostAgentClient.KillResult r = client().kill("localhost", List.of());

        assertEquals(0, r.attempted());
        assertFalse(called.get(), "expected no HTTP call for an empty target list");
    }

    @Test
    void failedCallReturnsFalseNotException() throws IOException {
        server.createContext("/v1/network/lift", exchange -> respondJson(exchange, 500, "{\"error\":\"boom\"}"));
        server.start();

        assertFalse(client().lift("localhost", "10.0.0.5"));
    }

    @Test
    void unreachableHostReturnsFalseNotException() {
        // No server started at all -- connection refused. This is the
        // case that matters most: one unreachable host must not throw an
        // exception that would abort the rest of the reclaim sequence.
        assertFalse(client().isolate("localhost", "10.0.0.5"));
    }

    @Test
    void persistenceScanReturnsFindingsList() throws IOException {
        server.createContext("/v1/persistence-scan", exchange ->
                respondJson(exchange, 200, "{\"findings\":[\"/etc/cron.d/x\",\"/root/.ssh/authorized_keys\"]}"));
        server.start();

        List<String> findings = client().persistenceScan("localhost", Instant.now());

        assertEquals(2, findings.size());
        assertTrue(findings.contains("/etc/cron.d/x"));
    }

    @Test
    void persistenceScanReturnsEmptyListOnFailureNotNull() {
        List<String> findings = client().persistenceScan("localhost", Instant.now());
        assertTrue(findings.isEmpty());
    }

    @Test
    void quarantineReturnsDestinationPath() throws IOException {
        server.createContext("/v1/quarantine", exchange ->
                respondJson(exchange, 200, "{\"quarantine_path\":\"/var/lib/sentinelmesh/quarantine/evt-1_x\"}"));
        server.start();

        String dest = client().quarantine("localhost", "/tmp/x", "evt-1");

        assertEquals("/var/lib/sentinelmesh/quarantine/evt-1_x", dest);
    }

    @Test
    void sandboxAnalyzeReturnsReportText() throws IOException {
        server.createContext("/v1/sandbox-analyze", exchange ->
                respondJson(exchange, 200, "{\"report\":\"=== analysis ===\"}"));
        server.start();

        String report = client().sandboxAnalyze("localhost", "/var/lib/sentinelmesh/quarantine/evt-1_x");

        assertEquals("=== analysis ===", report);
    }

    private static void respondJson(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
