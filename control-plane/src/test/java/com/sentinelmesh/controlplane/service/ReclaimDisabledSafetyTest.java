package com.sentinelmesh.controlplane.service;

import com.sentinelmesh.controlplane.audit.AuditLogger;
import com.sentinelmesh.controlplane.client.HostAgentClient;
import com.sentinelmesh.controlplane.client.LlmOrchestrationClient;
import com.sentinelmesh.controlplane.model.Incident;
import com.sentinelmesh.controlplane.repository.IncidentRepository;
import com.sentinelmesh.controlplane.repository.SecurityEventRepository;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class ReclaimDisabledSafetyTest {
    @Test
    void disabledReclaimIsAuditedBeforeAnyPrivilegedDependencyIsUsed() {
        AuditLogger audit = mock(AuditLogger.class);
        SecurityEventRepository events = mock(SecurityEventRepository.class);
        HostAgentClient agent = mock(HostAgentClient.class);
        IncidentRepository incidents = mock(IncidentRepository.class);
        CredentialRevocationClient credentials = mock(CredentialRevocationClient.class);
        LlmOrchestrationClient llm = mock(LlmOrchestrationClient.class);

        ReclaimProtocolService service = new ReclaimProtocolService(
                audit, events, agent, incidents, 15L, true, credentials, llm);
        ReflectionTestUtils.setField(service, "reclaimEnabled", false);

        Incident incident = new Incident();
        incident.setIncidentId("test-reclaim-disabled");
        service.run(incident);

        verify(audit).log(eq("test-reclaim-disabled"), eq("RECLAIM_DISABLED"),
                contains("sentinelmesh.reclaim.enabled=false"));
        verifyNoInteractions(events, agent, incidents, credentials, llm);
    }
}
