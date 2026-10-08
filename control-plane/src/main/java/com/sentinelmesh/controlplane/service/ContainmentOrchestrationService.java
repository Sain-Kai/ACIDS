package com.sentinelmesh.controlplane.service;

import com.sentinelmesh.controlplane.audit.AuditLogger;
import com.sentinelmesh.controlplane.client.HostAgentClient;
import com.sentinelmesh.controlplane.client.LlmOrchestrationClient;
import com.sentinelmesh.controlplane.dto.IncomingIncidentDTO;
import com.sentinelmesh.controlplane.mapper.EventMapper;
import com.sentinelmesh.controlplane.model.Incident;
import com.sentinelmesh.controlplane.model.SecurityEvent;
import com.sentinelmesh.controlplane.repository.IncidentRepository;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * Receives incidents forwarded from detection-engine (which already took
 * whatever immediate action its verdict called for). Persists the
 * event+incident, decides whether the reclaim protocol needs to run, runs
 * sandbox analysis on any quarantined artifact (via the host-agent running
 * on the host the artifact actually lives on), and -- once contained --
 * hands off to llm-orchestration for RCA/patch/judge.
 */
@Service
public class ContainmentOrchestrationService {

    private final AuditLogger auditLogger;
    private final ReclaimProtocolService reclaimProtocolService;
    private final IncidentRepository incidentRepository;
    private final EventMapper eventMapper;
    private final LlmOrchestrationClient llmOrchestrationClient;
    private final HostAgentClient hostAgentClient;

    public ContainmentOrchestrationService(AuditLogger auditLogger,
                                            ReclaimProtocolService reclaimProtocolService,
                                            IncidentRepository incidentRepository,
                                            EventMapper eventMapper,
                                            LlmOrchestrationClient llmOrchestrationClient,
                                            HostAgentClient hostAgentClient) {
        this.auditLogger = auditLogger;
        this.reclaimProtocolService = reclaimProtocolService;
        this.incidentRepository = incidentRepository;
        this.eventMapper = eventMapper;
        this.llmOrchestrationClient = llmOrchestrationClient;
        this.hostAgentClient = hostAgentClient;
    }

    public Incident handleIncomingIncident(IncomingIncidentDTO dto) { return handleIncomingIncident(dto, dto.incidentId); }

    public Incident handleIncomingIncident(IncomingIncidentDTO dto, String idempotencyKey) {
        if(idempotencyKey != null && !idempotencyKey.isBlank()){
            var existingByKey=incidentRepository.findByIdempotencyKey(idempotencyKey);
            if(existingByKey.isPresent()) return existingByKey.get();
        }
        SecurityEvent event = eventMapper.toEntity(dto.event);

        boolean escalate = dto.verdict != null && "escalate_to_reclaim".equals(dto.verdict.action);
        boolean quarantined = dto.verdict != null && "quarantine_file".equals(dto.verdict.action);

        if (dto.incidentId != null && incidentRepository.existsById(dto.incidentId)) {
            return incidentRepository.findById(dto.incidentId).orElseThrow();
        }

        Incident incident = new Incident();
        if (dto.incidentId != null) {
            incident.setIncidentId(dto.incidentId);
        }
        incident.setEvent(event);
        incident.setVerdictScore(dto.verdict != null ? dto.verdict.score : 0.0);
        incident.setMatchedRules(dto.verdict != null && dto.verdict.matchedRules != null
                ? String.join(",", dto.verdict.matchedRules) : "");
        incident.setActionTaken(dto.verdict != null ? dto.verdict.action : "unknown");
        incident.setActionError(dto.actionError);
        incident.setQuarantinePath(dto.quarantinePath);
        incident.setStatus(escalate ? Incident.Status.DETECTED : Incident.Status.CONTAINED);
        incident.setIdempotencyKey(idempotencyKey != null && !idempotencyKey.isBlank() ? idempotencyKey : incident.getIncidentId());

        try {
            incidentRepository.save(incident);
        } catch (DataIntegrityViolationException duplicate) {
            if (idempotencyKey != null && !idempotencyKey.isBlank()) {
                return incidentRepository.findByIdempotencyKey(idempotencyKey).orElseThrow(() -> duplicate);
            }
            throw duplicate;
        }

        auditLogger.log(incident.getIncidentId(), "INCIDENT_RECEIVED",
                "score=" + incident.getVerdictScore()
                        + " action=" + incident.getActionTaken()
                        + " rules=" + incident.getMatchedRules());

        if (escalate) {
            // Start reclaim asynchronously so the detector's durable incident
            // transport never waits on a long privileged workflow. The incident
            // remains isolated/active until the reclaim state machine finishes.
            reclaimProtocolService.runAsync(incident);
        }

        // "Executing suspicious payloads only inside a strongly isolated
        // sandbox when deeper behavioral analysis is necessary" -- gated
        // on there actually being a quarantined artifact to look at, and
        // run by the host-agent on whichever host actually has the file
        // (not assumed to be reachable from control-plane's own disk).
        String sandboxReport = "";
        if (quarantined && dto.quarantinePath != null && event.getHostname() != null) {
            sandboxReport = hostAgentClient.sandboxAnalyze(event.getHostname(), dto.quarantinePath);
        }

        // Post-containment handoff to the LLM layer (RCA -> patch ->
        // judge). Runs regardless of whether reclaim fired -- both paths
        // end with a contained/recovered incident that's worth analyzing.
        Map<String, Object> incidentContext = buildIncidentContext(incident, event, sandboxReport);
        if (incident.getStatus() != Incident.Status.DETECTED) {
            llmOrchestrationClient.analyzeAsync(incidentContext);
        }

        return incident;
    }

    private static Map<String, Object> buildIncidentContext(Incident incident, SecurityEvent event, String sandboxReport) {
        Map<String, Object> context = new HashMap<>();
        context.put("incident_id", incident.getIncidentId());
        context.put("score", incident.getVerdictScore());
        context.put("matched_rules", incident.getMatchedRules());
        context.put("action_taken", incident.getActionTaken());
        context.put("action_error", incident.getActionError() == null ? "" : incident.getActionError());
        context.put("quarantine_path", incident.getQuarantinePath() == null ? "" : incident.getQuarantinePath());
        context.put("status", incident.getStatus().name());
        context.put("event_id", event.getEventId());
        context.put("timestamp", event.getTimestamp() == null ? "" : event.getTimestamp().toString());
        context.put("source", event.getSource() == null ? "" : event.getSource());
        context.put("hostname", event.getHostname() == null ? "" : event.getHostname());
        context.put("host_ip", event.getHostIp() == null ? "" : event.getHostIp());
        context.put("event_type", event.getEventType() == null ? "" : event.getEventType());
        context.put("severity_raw", event.getSeverityRaw() == null ? "" : event.getSeverityRaw());
        context.put("process", Map.of(
                "pid", event.getProcessPid(),
                "ppid", event.getProcessPpid(),
                "exe", event.getProcessExe() == null ? "" : event.getProcessExe(),
                "cmdline", event.getProcessCmdline() == null ? "" : event.getProcessCmdline(),
                "user", event.getProcessUser() == null ? "" : event.getProcessUser()));
        context.put("network", Map.of(
                "src_ip", event.getNetworkSrcIp() == null ? "" : event.getNetworkSrcIp(),
                "dst_ip", event.getNetworkDstIp() == null ? "" : event.getNetworkDstIp(),
                "src_port", event.getNetworkSrcPort(),
                "dst_port", event.getNetworkDstPort(),
                "protocol", event.getNetworkProtocol() == null ? "" : event.getNetworkProtocol()));
        context.put("file", Map.of(
                "path", event.getFilePath() == null ? "" : event.getFilePath(),
                "operation", event.getFileOperation() == null ? "" : event.getFileOperation()));
        context.put("container", Map.of(
                "id", event.getContainerId() == null ? "" : event.getContainerId(),
                "image", event.getContainerImage() == null ? "" : event.getContainerImage()));
        context.put("tags", event.getTagsCsv() == null ? "" : event.getTagsCsv());
        if (sandboxReport != null && !sandboxReport.isEmpty()) context.put("sandbox_report", sandboxReport);
        return context;
    }
}
