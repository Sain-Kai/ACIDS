package com.sentinelmesh.controlplane.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;
import java.time.Duration;
import org.springframework.scheduling.annotation.Async;

import java.util.Map;

/**
 * Calls llm-orchestration's HTTP wrapper around orchestrator.handle_incident
 * (see llm-orchestration/app.py). Fire-and-forget from
 * ContainmentOrchestrationService's point of view -- this happens strictly
 * after containment, so a slow or failed LLM call must never block or
 * threaten the hot path (it can't: it's not even in the same process).
 */
@Component
public class LlmOrchestrationClient {

    private static final Logger log = LoggerFactory.getLogger(LlmOrchestrationClient.class);

    private final RestClient restClient;

    public LlmOrchestrationClient(@Value("${sentinelmesh.llm-orchestration-url}") String baseUrl,
                                   @Value("${sentinelmesh.security.llm-orchestration-api-key}") String apiKey) {
        HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(httpClient);
        requestFactory.setReadTimeout(Duration.ofSeconds(30));
        this.restClient = RestClient.builder()
                .baseUrl(baseUrl)
                .requestFactory(requestFactory)
                .defaultHeader("X-SentinelMesh-Api-Key", apiKey)
                .build();
    }

    @Async("sentinelMeshAsyncExecutor")
    public void analyzeAsync(Map<String, Object> incidentContext) {
        // Post-containment only. The bounded executor keeps model latency
        // away from the incident HTTP request thread and from the P0 path.
        Exception last = null;
        for (int attempt = 1; attempt <= 3; attempt++) {
            try {
                restClient.post()
                        .uri("/handle-incident")
                        .body(incidentContext)
                        .retrieve()
                        .toBodilessEntity();
                return;
            } catch (Exception e) {
                last = e;
                if (attempt < 3) {
                    try { Thread.sleep(250L * (1L << (attempt - 1))); }
                    catch (InterruptedException ie) { Thread.currentThread().interrupt(); return; }
                }
            }
        }
        log.warn("llm-orchestration call failed after retries: {}", last == null ? "unknown" : last.getMessage());
    }
}
