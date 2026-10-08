package com.sentinelmesh.controlplane.service;

import com.sentinelmesh.controlplane.audit.AuditLogger;
import com.sentinelmesh.controlplane.client.HostAgentClient;
import com.sentinelmesh.controlplane.model.Incident;
import com.sentinelmesh.controlplane.model.SecurityEvent;
import com.sentinelmesh.controlplane.repository.IncidentRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Independent missed-attack detector. It does not trust the original
 * detector to have seen the compromise; it asks each active host-agent for
 * persistence indicators and escalates on positive evidence. */
@Component
public class CompromiseDetectionScheduler {
    private final IncidentRepository incidents;
    private final HostAgentClient hostAgentClient;
    private final ReclaimProtocolService reclaim;
    private final AuditLogger auditLogger;
    private final long lookbackMinutes;

    public CompromiseDetectionScheduler(IncidentRepository incidents,
                                        HostAgentClient hostAgentClient, ReclaimProtocolService reclaim,
                                        AuditLogger auditLogger,
                                        @Value("${sentinelmesh.compromise.lookback-minutes:10}") long lookbackMinutes) {
        this.incidents = incidents; this.hostAgentClient = hostAgentClient;
        this.reclaim = reclaim; this.auditLogger = auditLogger; this.lookbackMinutes = lookbackMinutes;
    }

    @Scheduled(fixedDelayString = "${sentinelmesh.compromise.check-interval-seconds:60}000")
    public void detectMissedCompromise() {
        Instant now = Instant.now();
        List<String> hosts = hostAgentClient.hosts();
        for (String host : hosts) {
            if (host == null || host.isBlank()) continue;
            HostAgentClient.ScanResult scan = hostAgentClient.persistenceScanDetailed(host, now.minusSeconds(lookbackMinutes * 60));
            if (!scan.reachable() || !scan.success()) {
                auditLogger.log("SYSTEM", "HOST_AGENT_SCAN_FAILED", "host=" + host + " reason=" + scan.message());
                continue;
            }
            List<String> findings = scan.findings();
            if (findings.isEmpty()) continue;

            var open = incidents.findFirstByEventHostnameAndStatusInOrderByCreatedAtDesc(host,
                    List.of(Incident.Status.RECLAIM_IN_PROGRESS, Incident.Status.RECLAIM_NEEDS_REVIEW, Incident.Status.DETECTED));
            if (open.isPresent()) continue;

            HostAgentClient.Identity identity = hostAgentClient.identity(host);
            if (identity.ip().isBlank()) {
                auditLogger.log("SYSTEM", "COMPROMISE_SIGNAL_UNBOUND", "host=" + host + " reason=host-agent identity unavailable");
                continue;
            }

            Incident incident = new Incident();
            SecurityEvent event = new SecurityEvent();
            event.setEventId(UUID.randomUUID().toString());
            event.setTimestamp(now);
            event.setSource("manual");
            event.setHostname(host);
            event.setHostIp(identity.ip());
            event.setEventType("compromise_signal");
            event.setSeverityRaw("critical");
            event.setRawPayloadJson(serialize(findings));
            incident.setEvent(event);
            incident.setVerdictScore(0.99);
            incident.setMatchedRules("independent_persistence_check");
            incident.setActionTaken("escalate_to_reclaim");
            incident.setStatus(Incident.Status.RECLAIM_IN_PROGRESS);
            incidents.save(incident);
            auditLogger.log(incident.getIncidentId(), "MISSED_ATTACK_DETECTED", "host=" + host + " findings=" + findings.size());
            reclaim.run(incident);
        }
    }

    private String serialize(Object value) {
        return value instanceof List<?> list ? list.toString() : Map.of("value", value).toString();
    }
}
