package com.sentinelmesh.controlplane.service;

import com.sentinelmesh.controlplane.audit.AuditLogger;
import com.sentinelmesh.controlplane.model.Incident;
import com.sentinelmesh.controlplane.repository.IncidentRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;

/** Resumes checkpointed reclaim workflows after a control-plane restart or
 * transient orchestration failure. Each protocol stage is checkpointed in
 * Incident.reclaimState before its privileged work begins. */
@Component
public class ReclaimRecoveryScheduler {
    private final IncidentRepository incidentRepository;
    private final ReclaimProtocolService reclaimProtocolService;
    private final AuditLogger auditLogger;

    public ReclaimRecoveryScheduler(IncidentRepository incidentRepository,
                                     ReclaimProtocolService reclaimProtocolService,
                                     AuditLogger auditLogger) {
        this.incidentRepository = incidentRepository;
        this.reclaimProtocolService = reclaimProtocolService;
        this.auditLogger = auditLogger;
    }

    @Scheduled(fixedDelayString = "${sentinelmesh.reclaim.resume-check-interval-seconds:30}000")
    public void resumeInterruptedReclaims() {
        List<Incident> pending = incidentRepository.findByStatusOrderByCreatedAtAsc(Incident.Status.RECLAIM_IN_PROGRESS);
        for (Incident incident : pending) {
            try {
                auditLogger.log(incident.getIncidentId(), "RECLAIM_RESUME", "resuming checkpoint=" + incident.getReclaimState());
                reclaimProtocolService.run(incident);
            } catch (RuntimeException ex) {
                auditLogger.log(incident.getIncidentId(), "RECLAIM_RESUME_FAILED", ex.getClass().getSimpleName() + ": " + ex.getMessage());
            }
        }
    }
}
