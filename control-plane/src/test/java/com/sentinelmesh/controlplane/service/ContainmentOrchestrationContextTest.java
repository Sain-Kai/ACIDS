package com.sentinelmesh.controlplane.service;

import com.sentinelmesh.controlplane.model.Incident;
import com.sentinelmesh.controlplane.model.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ContainmentOrchestrationContextTest {

    @Test
    void contextBuilderHandlesMissingOptionalTelemetry() {
        Incident incident = new Incident();
        incident.setIncidentId("context-null-test");
        incident.setStatus(Incident.Status.CONTAINED);
        incident.setVerdictScore(0.91);
        incident.setMatchedRules("test-rule");
        incident.setActionTaken("block_network");

        SecurityEvent event = new SecurityEvent();
        event.setEventId("event-null-test");

        Map<String, Object> context =
            ContainmentOrchestrationService.buildIncidentContext(incident, event, "");

        assertNotNull(context.get("process"));
        assertNotNull(context.get("network"));

        Map<?, ?> process = (Map<?, ?>) context.get("process");
        Map<?, ?> network = (Map<?, ?>) context.get("network");

        assertTrue(process.containsKey("pid"));
        assertNull(process.get("pid"));
        assertTrue(process.containsKey("ppid"));
        assertNull(process.get("ppid"));
        assertTrue(network.containsKey("src_port"));
        assertNull(network.get("src_port"));
        assertTrue(network.containsKey("dst_port"));
        assertNull(network.get("dst_port"));
    }
}
