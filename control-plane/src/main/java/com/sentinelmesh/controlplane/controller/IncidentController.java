package com.sentinelmesh.controlplane.controller;

import com.sentinelmesh.controlplane.dto.IncomingIncidentDTO;
import com.sentinelmesh.controlplane.dto.IncomingCompromiseSignalDTO;
import com.sentinelmesh.controlplane.model.SecurityEvent;
import com.sentinelmesh.controlplane.client.HostAgentClient;
import java.util.UUID;
import com.sentinelmesh.controlplane.model.Incident;
import com.sentinelmesh.controlplane.repository.IncidentRepository;
import com.sentinelmesh.controlplane.service.ContainmentOrchestrationService;
import com.sentinelmesh.controlplane.service.ReclaimProtocolService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.Authentication;

import java.util.Map;
import java.util.NoSuchElementException;

@RestController
@RequestMapping("/incidents")
public class IncidentController {

    private final ContainmentOrchestrationService containmentOrchestrationService;
    private final ReclaimProtocolService reclaimProtocolService;
    private final IncidentRepository incidentRepository;
    private final HostAgentClient hostAgentClient;

    public IncidentController(ContainmentOrchestrationService containmentOrchestrationService,
                               ReclaimProtocolService reclaimProtocolService,
                               IncidentRepository incidentRepository,
                               HostAgentClient hostAgentClient) {
        this.containmentOrchestrationService = containmentOrchestrationService;
        this.reclaimProtocolService = reclaimProtocolService;
        this.incidentRepository = incidentRepository;
        this.hostAgentClient = hostAgentClient;
    }

    /** Receives incidents forwarded from detection-engine's
     *  internal/incident.Forward(). Body shape is IncomingIncidentDTO. */
    @PostMapping
    public Map<String, String> receiveIncident(@Valid @RequestBody IncomingIncidentDTO dto, @RequestHeader(value="Idempotency-Key", required=false) String idempotencyKey, Authentication auth) {
        require(auth, "detection-engine");
        Incident incident = containmentOrchestrationService.handleIncomingIncident(dto, idempotencyKey);
        return Map.of("incident_id", incident.getIncidentId(), "status", incident.getStatus().name());
    }

    @GetMapping
    public java.util.List<Incident> listRecent(@RequestParam(defaultValue="20") int limit, Authentication auth) {
        require(auth, "detection-engine", "security-automation");
        int bounded = Math.max(1, Math.min(limit, 100));
        return incidentRepository.findTop100ByOrderByCreatedAtDesc().stream().limit(bounded).toList();
    }

    @GetMapping("/{id}")
    public Incident getIncident(@PathVariable String id, Authentication auth) {
        require(auth, "detection-engine", "security-automation", "llm-orchestration");
        return incidentRepository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("no such incident: " + id));
    }

    /** Manual trigger -- for an externally-sourced compromise signal that
     *  didn't come through detection-engine's normal escalation path. */
    @PostMapping("/compromise-signals")
    public Map<String, String> receiveCompromiseSignal(@Valid @RequestBody IncomingCompromiseSignalDTO dto, Authentication auth) {
        require(auth, "detection-engine", "security-automation");
        if (!hostAgentClient.registered(dto.hostname)) {
            throw new IllegalArgumentException("unknown protected host: " + dto.hostname);
        }
        HostAgentClient.Identity identity = hostAgentClient.identity(dto.hostname);
        if (identity.ip() == null || identity.ip().isBlank() || !identity.ip().equals(dto.hostIp)) {
            throw new IllegalArgumentException("compromise signal host identity does not match the registered host-agent");
        }
        if (identity.hostname() == null || identity.hostname().isBlank() || !identity.hostname().equals(dto.hostname)) {
            throw new IllegalArgumentException("compromise signal hostname does not match the registered host-agent");
        }
        Incident incident = new Incident();
        SecurityEvent event = new SecurityEvent();
        event.setEventId(UUID.randomUUID().toString());
        event.setTimestamp(java.time.Instant.now());
        event.setSource("manual");
        event.setHostname(dto.hostname);
        event.setHostIp(dto.hostIp);
        event.setEventType("compromise_signal");
        event.setSeverityRaw("critical");
        event.setProcessUser(dto.username);
        event.setRawPayloadJson("category=" + dto.category + ";indicators=" + dto.indicators);
        incident.setEvent(event);
        incident.setVerdictScore(0.99);
        incident.setMatchedRules("external_compromise_signal:" + dto.category);
        incident.setActionTaken("escalate_to_reclaim");
        incident.setStatus(Incident.Status.RECLAIM_IN_PROGRESS);
        incidentRepository.save(incident);
        reclaimProtocolService.runAsync(incident);
        return Map.of("incident_id", incident.getIncidentId(), "status", incident.getStatus().name());
    }

    @PostMapping("/{id}/reclaim")
    public Map<String, String> triggerReclaim(@PathVariable String id, Authentication auth) {
        require(auth, "detection-engine", "security-automation");
        Incident incident = incidentRepository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("no such incident: " + id));
        reclaimProtocolService.run(incident);
        incidentRepository.save(incident);
        return Map.of("incident_id", incident.getIncidentId(), "status", incident.getStatus().name());
    }

    /** Explicit security-review approval for a fail-closed reclaim that stopped at
     * RECLAIM_NEEDS_REVIEW. The workflow resumes from the persisted next step;
     * it never skips a privileged action merely because approval arrived later. */
    @PostMapping("/{id}/reclaim/approve")
    public Map<String, String> approveReclaim(@PathVariable String id, Authentication auth) {
        require(auth, "security-automation");
        Incident incident = incidentRepository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("no such incident: " + id));
        if (incident.getStatus() != Incident.Status.RECLAIM_NEEDS_REVIEW) {
            throw new IllegalStateException("incident is not awaiting reclaim approval: " + incident.getStatus());
        }
        incident.setStatus(Incident.Status.RECLAIM_IN_PROGRESS);
        incidentRepository.save(incident);
        reclaimProtocolService.run(incident);
        incidentRepository.save(incident);
        return Map.of("incident_id", incident.getIncidentId(), "status", incident.getStatus().name());
    }
    private static void require(Authentication auth, String... allowed){
        String who=auth==null?"":auth.getName();
        for(String a:allowed) if(a.equals(who)) return;
        throw new org.springframework.security.access.AccessDeniedException("caller not authorized for this operation");
    }
}
