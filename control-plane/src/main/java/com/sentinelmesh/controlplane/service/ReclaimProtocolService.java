package com.sentinelmesh.controlplane.service;

import com.sentinelmesh.controlplane.audit.AuditLogger;
import com.sentinelmesh.controlplane.client.HostAgentClient;
import com.sentinelmesh.controlplane.client.LlmOrchestrationClient;
import com.sentinelmesh.controlplane.model.Incident;
import com.sentinelmesh.controlplane.model.ReclaimState;
import com.sentinelmesh.controlplane.model.SecurityEvent;
import com.sentinelmesh.controlplane.repository.IncidentRepository;
import com.sentinelmesh.controlplane.repository.SecurityEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

/**
 * Durable, fail-closed P1 reclaim protocol.
 *
 * ReclaimState means "the next step to execute", not "the last step that
 * completed". Each privileged stage is therefore idempotent and safe to
 * repeat after a crash that occurs after the checkpoint but before the
 * success transition is persisted. Recovery is never attempted after a
 * failed containment, restore, verification, or credential-revocation step.
 */
@Service
public class ReclaimProtocolService {
    private static final Logger log = LoggerFactory.getLogger(ReclaimProtocolService.class);
    private final AuditLogger auditLogger;
    private final SecurityEventRepository eventRepo;
    private final HostAgentClient agent;
    private final IncidentRepository incidentRepo;
    private final Duration correlationWindow;
    private final boolean requireRestore;
    private final CredentialRevocationClient credentials;
    private final LlmOrchestrationClient llmOrchestrationClient;
    private final ConcurrentHashMap<String, ReentrantLock> locks = new ConcurrentHashMap<>();

    public ReclaimProtocolService(AuditLogger auditLogger,
                                   SecurityEventRepository eventRepo,
                                   HostAgentClient agent,
                                   IncidentRepository incidentRepo,
                                   @Value("${sentinelmesh.reclaim.correlation-window-minutes:15}") long windowMinutes,
                                   @Value("${sentinelmesh.reclaim.require-restore-success:true}") boolean requireRestore,
                                   CredentialRevocationClient credentials,
                                   LlmOrchestrationClient llmOrchestrationClient) {
        this.auditLogger = auditLogger;
        this.eventRepo = eventRepo;
        this.agent = agent;
        this.incidentRepo = incidentRepo;
        this.correlationWindow = Duration.ofMinutes(windowMinutes);
        this.requireRestore = requireRestore;
        this.credentials = credentials;
        this.llmOrchestrationClient = llmOrchestrationClient;
    }

    @org.springframework.scheduling.annotation.Async("sentinelMeshAsyncExecutor")
    public void runAsync(Incident incident) {
        run(incident);
    }

    public void run(Incident incident) {
        ReentrantLock lock = locks.computeIfAbsent(incident.getIncidentId(), id -> new ReentrantLock());
        lock.lock();
        try {
            runLocked(incident);
        } finally {
            lock.unlock();
            if (!lock.hasQueuedThreads()) {
                locks.remove(incident.getIncidentId(), lock);
            }
        }
    }

    private void runLocked(Incident incident) {
        String host = hostnameOf(incident);
        if (host == null || host.isBlank()) {
            fail(incident, "missing protected host identity");
            return;
        }
        if (!agent.registered(host)) {
            fail(incident, "protected host is not registered: " + host);
            return;
        }
        HostAgentClient.Identity identity = agent.identity(host);
        String expectedIp = incident.getEvent() == null ? "" : incident.getEvent().getHostIp();
        if (identity.hostname() == null || !host.equals(identity.hostname()) || identity.ip() == null || identity.ip().isBlank() || expectedIp == null || !expectedIp.equals(identity.ip())) {
            fail(incident, "protected host identity verification failed; refusing privileged reclaim actions");
            return;
        }
        if (incident.getStatus() == Incident.Status.RECLAIM_COMPLETE || incident.getStatus() == Incident.Status.RESOLVED) {
            return;
        }
        if (incident.getStatus() == Incident.Status.RECLAIM_NEEDS_REVIEW) {
            // Human/security-automation approval is expected to set the incident
            // back to IN_PROGRESS before asking for an automatic continuation.
            auditLogger.log(incident.getIncidentId(), "RECLAIM_BLOCKED", "incident requires explicit review before continuation");
            return;
        }

        if (incident.getStatus() == Incident.Status.DETECTED || incident.getStatus() == Incident.Status.CONTAINED) {
            incident.setStatus(Incident.Status.RECLAIM_IN_PROGRESS);
            if (incident.getReclaimState() == null) {
                incident.setReclaimState(ReclaimState.CONTAIN);
            }
            checkpoint(incident);
        } else if (incident.getStatus() != Incident.Status.RECLAIM_IN_PROGRESS) {
            incident.setStatus(Incident.Status.RECLAIM_IN_PROGRESS);
            if (incident.getReclaimState() == null) incident.setReclaimState(ReclaimState.CONTAIN);
            checkpoint(incident);
        }

        List<SecurityEvent> correlated = List.of();
        int verifyRemediationPasses = 0;
        for (;;) {
            ReclaimState state = incident.getReclaimState();
            if (state == null) {
                incident.setReclaimState(ReclaimState.CONTAIN);
                checkpoint(incident);
                state = ReclaimState.CONTAIN;
            }
            switch (state) {
                case CONTAIN -> {
                    checkpointStep(incident, "CONTAIN");
                    if (!contain(incident, host)) return;
                    advance(incident, ReclaimState.IDENTIFY);
                }
                case IDENTIFY -> {
                    correlated = identify(incident, host);
                    advance(incident, ReclaimState.TERMINATE);
                }
                case TERMINATE -> {
                    if (correlated.isEmpty()) correlated = identify(incident, host);
                    if (!terminate(incident, host, correlated)) return;
                    advance(incident, ReclaimState.QUARANTINE);
                }
                case QUARANTINE -> {
                    if (correlated.isEmpty()) correlated = identify(incident, host);
                    if (!quarantine(incident, host, correlated)) return;
                    advance(incident, ReclaimState.FORENSIC_SNAPSHOT);
                }
                case FORENSIC_SNAPSHOT -> {
                    if (!forensicSnapshot(incident, host)) return;
                    advance(incident, ReclaimState.REVOKE_ROTATE);
                }
                case REVOKE_ROTATE -> {
                    if (!revokeAndRotate(incident, host)) return;
                    advance(incident, ReclaimState.RESTORE);
                }
                case RESTORE -> {
                    if (correlated.isEmpty()) correlated = identify(incident, host);
                    if (!restore(incident, host, correlated)) return;
                    advance(incident, ReclaimState.VERIFY);
                }
                case VERIFY -> {
                    HostAgentClient.ScanResult scan = verify(incident, host);
                    if (!scan.reachable() || !scan.success()) {
                        review(incident, "verification failed: " + scan.message());
                        return;
                    }
                    if (!scan.findings().isEmpty()) {
                        if (++verifyRemediationPasses > 3) {
                            review(incident, "persistence findings remain after three remediation passes: " + String.join(", ", scan.findings()));
                            return;
                        }
                        // Persistence findings are themselves compromised artifacts.
                        // Quarantine them before a second verification pass rather
                        // than merely alerting and leaving the host isolated forever.
                        int remediated = 0;
                        for (String finding : scan.findings()) {
                            HostAgentClient.QuarantineResult q = agent.quarantineDetailed(host, finding, incident.getIncidentId());
                            if (!q.reachable() || !q.success()) {
                                review(incident, "persistence remediation failed for " + finding + ": " + q.message());
                                return;
                            }
                            remediated++;
                        }
                        auditLogger.log(incident.getIncidentId(), "VERIFY_REMEDIATE", "host=" + host + " quarantined_persistence_findings=" + remediated + " pass=" + verifyRemediationPasses);
                        continue;
                    }
                    advance(incident, ReclaimState.RECOVER);
                }
                case RECOVER -> {
                    if (!recover(incident, host)) return;
                    advance(incident, ReclaimState.DONE);
                }
                case DONE -> {
                    incident.setStatus(Incident.Status.RECLAIM_COMPLETE);
                    checkpoint(incident);
                    auditLogger.log(incident.getIncidentId(), "RECLAIM_COMPLETE", "reclaim protocol finished");
                    dispatchPostContainmentAnalysis(incident, host);
                    return;
                }
            }
        }
    }

    /** Mark the step as the next executable action. The step itself may be repeated. */
    private void checkpointStep(Incident incident, String stage) {
        auditLogger.log(incident.getIncidentId(), "RECLAIM_STEP_BEGIN", "stage=" + stage + " checkpoint=" + incident.getReclaimState());
        checkpoint(incident);
    }

    private void advance(Incident incident, ReclaimState next) {
        incident.setReclaimState(next);
        checkpoint(incident);
        auditLogger.log(incident.getIncidentId(), "RECLAIM_STEP_COMPLETE", "next=" + next);
    }

    private boolean contain(Incident incident, String host) {
        String ip = incident.getEvent() != null ? incident.getEvent().getHostIp() : null;
        if (ip == null || ip.isBlank()) {
            fail(incident, "missing host IP for containment isolation");
            return false;
        }
        HostAgentClient.OperationResult iso = agent.isolateDetailed(host, ip);
        if (!iso.success() || !iso.reachable()) {
            fail(incident, "containment isolation failed: " + iso.message());
            return false;
        }
        if (incident.getEvent() != null && incident.getEvent().getProcessPid() != null && incident.getEvent().getProcessExe() != null) {
            HostAgentClient.KillOperationResult k = agent.killDetailed(host,
                    List.of(new HostAgentClient.KillTarget(incident.getEvent().getProcessPid(), incident.getEvent().getProcessExe())));
            if (!k.reachable()) {
                fail(incident, "trigger process termination agent unavailable: " + k.message());
                return false;
            }
            if (!k.success()) {
                fail(incident, "triggering process termination failed: " + k.message());
                return false;
            }
            // A verified PID/exe mismatch means the process has already exited
            // or PID reuse was detected; that is safe to treat as terminated.
        }
        auditLogger.log(incident.getIncidentId(), "CONTAIN", "isolation applied and trigger process termination attempted on host=" + host);
        return true;
    }

    private List<SecurityEvent> identify(Incident incident, String host) {
        Instant center = incident.getCreatedAt();
        List<SecurityEvent> rows = eventRepo.findByHostnameAndTimestampBetween(
                host, center.minus(correlationWindow), center.plus(correlationWindow));
        auditLogger.log(incident.getIncidentId(), "IDENTIFY", "host=" + host + " correlated_events=" + rows.size());
        return rows;
    }

    private boolean terminate(Incident incident, String host, List<SecurityEvent> correlated) {
        List<HostAgentClient.KillTarget> targets = correlated.stream()
                .filter(e -> e.getProcessPid() != null && e.getProcessExe() != null)
                .map(e -> new HostAgentClient.KillTarget(e.getProcessPid(), e.getProcessExe()))
                .distinct()
                .collect(Collectors.toList());
        HostAgentClient.KillOperationResult op = agent.killDetailed(host, targets);
        if (!op.reachable()) {
            fail(incident, "host-agent unavailable during process termination: " + op.message());
            return false;
        }
        if (!op.success()) {
            fail(incident, "process termination action failed: " + op.message());
            return false;
        }
        HostAgentClient.KillResult r = op.result();
        auditLogger.log(incident.getIncidentId(), "TERMINATE", "host=" + host + " attempted=" + r.attempted() + " killed=" + r.killed() + " skipped=" + r.skipped());
        return true;
    }

    private boolean quarantine(Incident incident, String host, List<SecurityEvent> correlated) {
        int candidates = 0;
        int success = 0;
        for (SecurityEvent e : correlated) {
            boolean write = "write".equals(e.getFileOperation()) || "create".equals(e.getFileOperation()) || "modify".equals(e.getFileOperation());
            if (!write || e.getFilePath() == null || e.getFilePath().isBlank()) continue;
            if (incident.getEvent() != null && e.getEventId() != null && e.getEventId().equals(incident.getEvent().getEventId())) continue;
            candidates++;
            HostAgentClient.QuarantineResult op = agent.quarantineDetailed(host, e.getFilePath(), e.getEventId());
            if (op.success() && (incident.getQuarantinePath() == null || incident.getQuarantinePath().isBlank())) {
                incident.setQuarantinePath(op.path());
                checkpoint(incident);
            }
            if (!op.reachable()) {
                fail(incident, "host-agent unavailable during artifact quarantine: " + op.message());
                return false;
            }
            if (!op.success()) {
                fail(incident, "failed to quarantine correlated artifact: " + op.message());
                return false;
            }
            success++;
        }
        // A high-confidence incident's already-known triggering artifact is
        // handled by the detector before this protocol. Correlated writes are
        // best-effort discovery, but an inability to reach the agent is fatal.
        if (candidates > 0 && success < candidates) {
            fail(incident, "failed to quarantine " + (candidates - success) + " correlated artifact(s)");
            return false;
        }
        auditLogger.log(incident.getIncidentId(), "QUARANTINE", "host=" + host + " success=" + success + " candidates=" + candidates);
        return true;
    }

    private boolean forensicSnapshot(Incident incident, String host) {
        String snapshotId = agent.snapshotId(host);
        if (snapshotId.isBlank()) {
            fail(incident, "forensic snapshot could not be created on protected host");
            return false;
        }
        auditLogger.log(incident.getIncidentId(), "FORENSIC_SNAPSHOT", "host=" + host + " snapshot_id=" + snapshotId);
        return true;
    }

    private boolean revokeAndRotate(Incident incident, String host) {
        String user = incident.getEvent() != null ? incident.getEvent().getProcessUser() : null;
        if (user != null && !user.isBlank()) {
            if (!agent.lockAccount(host, user)) {
                fail(incident, "local credential revocation failed for user=" + user);
                return false;
            }
        } else {
            auditLogger.log(incident.getIncidentId(), "REVOKE_LOCAL_SKIP", "no local username in evidence");
        }
        String category = incident.getEvent() != null ? incident.getEvent().getEventType() : "unknown";
        // The external adapter is evaluated independently of local account presence
        // so cloud/service credentials can still be revoked for non-Linux identities.
        if (!credentials.revoke(incident.getIncidentId(), host, user == null ? "" : user, category)) {
            fail(incident, "external credential revocation webhook failed");
            return false;
        }
        auditLogger.log(incident.getIncidentId(), "REVOKE_ROTATE", "credential revocation connector completed; local_account_locked=" + (user != null && !user.isBlank()));
        return true;
    }

    private boolean restore(Incident incident, String host, List<SecurityEvent> correlated) {
        Set<String> paths = correlated.stream()
                .map(SecurityEvent::getFilePath)
                .filter(p -> p != null && !p.isBlank())
                .collect(Collectors.toSet());
        if (incident.getEvent() != null && incident.getEvent().getFilePath() != null) {
            paths.add(incident.getEvent().getFilePath());
        }
        int attempted = 0;
        int ok = 0;
        for (String path : paths) {
            attempted++;
            HostAgentClient.OperationResult r = agent.restoreDetailed(host, path, incident.getCreatedAt());
            if (r.success()) ok++;
            else if (!r.reachable()) {
                fail(incident, "restore agent unavailable: " + r.message());
                return false;
            }
        }
        if (requireRestore && attempted > 0 && ok < attempted) {
            fail(incident, "one or more affected paths could not be restored from a pre-incident snapshot");
            return false;
        }
        auditLogger.log(incident.getIncidentId(), "RESTORE", "host=" + host + " restored=" + ok + " attempted=" + attempted);
        return true;
    }

    private HostAgentClient.ScanResult verify(Incident incident, String host) {
        HostAgentClient.ScanResult r = agent.persistenceScanDetailed(host, incident.getCreatedAt());
        auditLogger.log(incident.getIncidentId(), "VERIFY", "host=" + host + " reachable=" + r.reachable() + " success=" + r.success() + " findings=" + r.findings().size());
        return r;
    }

    private boolean recover(Incident incident, String host) {
        String ip = incident.getEvent() != null ? incident.getEvent().getHostIp() : null;
        if (ip == null || ip.isBlank()) {
            fail(incident, "missing host IP for safe recovery");
            return false;
        }
        HostAgentClient.OperationResult r = agent.liftDetailed(host, ip);
        if (!r.success() || !r.reachable()) {
            fail(incident, "failed to lift isolation: " + r.message());
            return false;
        }
        auditLogger.log(incident.getIncidentId(), "RECOVER", "isolation lifted host=" + host + " ip=" + ip);
        return true;
    }

    private void review(Incident i, String detail) {
        i.setStatus(Incident.Status.RECLAIM_NEEDS_REVIEW);
        checkpoint(i);
        auditLogger.log(i.getIncidentId(), "RECLAIM_NEEDS_REVIEW", detail);
    }

    private void fail(Incident i, String detail) {
        i.setStatus(Incident.Status.RECLAIM_NEEDS_REVIEW);
        checkpoint(i);
        auditLogger.log(i.getIncidentId(), "RECLAIM_FAILED_CLOSED", detail);
    }

    private void checkpoint(Incident i) {
        try {
            incidentRepo.save(i);
        } catch (RuntimeException ex) {
            log.error("reclaim checkpoint failure incident={}", i.getIncidentId(), ex);
            throw ex;
        }
    }

    private void dispatchPostContainmentAnalysis(Incident incident, String host) {
        Map<String, Object> context = new LinkedHashMap<>();
        context.put("incident_id", incident.getIncidentId());
        context.put("status", incident.getStatus().name());
        context.put("event", eventContext(incident.getEvent()));
        context.put("verdict_score", incident.getVerdictScore());
        context.put("matched_rules", incident.getMatchedRules() == null ? "" : incident.getMatchedRules());
        context.put("action_taken", incident.getActionTaken() == null ? "" : incident.getActionTaken());
        context.put("action_error", incident.getActionError() == null ? "" : incident.getActionError());
        context.put("quarantine_path", incident.getQuarantinePath() == null ? "" : incident.getQuarantinePath());
        context.put("protected_host", host);
        if (incident.getQuarantinePath() != null && !incident.getQuarantinePath().isBlank()) {
            String report = agent.sandboxAnalyze(host, incident.getQuarantinePath());
            if (!report.isBlank()) context.put("sandbox_report", report);
            else auditLogger.log(incident.getIncidentId(), "SANDBOX_UNAVAILABLE", "post-reclaim artifact analysis returned no report; incident remains recovered");
        }
        llmOrchestrationClient.analyzeAsync(context);
        auditLogger.log(incident.getIncidentId(), "LLM_ANALYSIS_DISPATCHED", "post-reclaim analysis requested after successful recovery");
    }

    private Map<String, Object> eventContext(SecurityEvent e) {
        if (e == null) return Map.of();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("event_id", e.getEventId());
        out.put("correlation_id", e.getCorrelationId());
        out.put("timestamp", e.getTimestamp());
        out.put("source", e.getSource());
        out.put("hostname", e.getHostname());
        out.put("host_ip", e.getHostIp());
        out.put("event_type", e.getEventType());
        out.put("severity_raw", e.getSeverityRaw());
        out.put("process_pid", e.getProcessPid());
        out.put("process_ppid", e.getProcessPpid());
        out.put("process_exe", e.getProcessExe());
        out.put("process_cmdline", e.getProcessCmdline());
        out.put("process_user", e.getProcessUser());
        out.put("network_src_ip", e.getNetworkSrcIp());
        out.put("network_dst_ip", e.getNetworkDstIp());
        out.put("network_src_port", e.getNetworkSrcPort());
        out.put("network_dst_port", e.getNetworkDstPort());
        out.put("network_protocol", e.getNetworkProtocol());
        out.put("file_path", e.getFilePath());
        out.put("file_operation", e.getFileOperation());
        out.put("tags", e.getTagsCsv());
        out.put("container_id", e.getContainerId());
        out.put("container_image", e.getContainerImage());
        out.put("raw_payload", e.getRawPayloadJson());
        return out;
    }

    private String hostnameOf(Incident i) {
        return i.getEvent() == null ? null : i.getEvent().getHostname();
    }
}
