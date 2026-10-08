package com.sentinelmesh.controlplane.model;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

/**
 * A defensive policy change that passed the Security Judge, moving through a
 * canary -> promote (or rollback) lifecycle. GuardedDeployService signs the
 * constrained manifest and applies it through the registered host-agents,
 * with explicit canary, rollback, and fail-closed review states.
 */
@Entity
@Table(name = "guarded_deployments")
public class GuardedDeployment {

    public enum Stage { STAGED, CANARY, PROMOTED, ROLLED_BACK, FAILED_NEEDS_REVIEW }

    @Id
    private String deploymentId = UUID.randomUUID().toString();

    private String incidentId;

    /** Comma-separated rule names this patch targets, threaded through
     *  from the triggering incident (see ContainmentOrchestrationService
     *  -> orchestrator.py -> here). Used by CanaryPromotionScheduler to
     *  check whether the incident rate for these specific rules actually
     *  improved during the canary window. May be blank if the incident
     *  matched no named rule, in which case the scheduler rejects promotion because there is no
     *  measurable rule-level safety signal. */
    private String matchedRules;

    @Lob
    private String proposedChange;

    @Lob
    private String judgeRationale;

    @Enumerated(EnumType.STRING)
    private Stage stage = Stage.STAGED;

    @Lob private String signedPolicy;
    @Lob private String previousPolicy;
    @Column(length = 4000) private String targetHosts;
    private String canaryHost;
    private Instant canaryStartedAt;
    private Instant createdAt = Instant.now();
    private Instant updatedAt = Instant.now();

    public String getDeploymentId() { return deploymentId; }
    public String getIncidentId() { return incidentId; }
    public void setIncidentId(String incidentId) { this.incidentId = incidentId; }
    public String getMatchedRules() { return matchedRules; }
    public void setMatchedRules(String matchedRules) { this.matchedRules = matchedRules; }
    public String getProposedChange() { return proposedChange; }
    public void setProposedChange(String proposedChange) { this.proposedChange = proposedChange; }
    public String getJudgeRationale() { return judgeRationale; }
    public void setJudgeRationale(String judgeRationale) { this.judgeRationale = judgeRationale; }
    public Stage getStage() { return stage; }
    public void setStage(Stage stage) { this.stage = stage; this.updatedAt = Instant.now(); }
    public String getSignedPolicy(){return signedPolicy;} public void setSignedPolicy(String v){signedPolicy=v;}
    public String getPreviousPolicy(){return previousPolicy;} public void setPreviousPolicy(String v){previousPolicy=v;}
    public String getTargetHosts(){return targetHosts;} public void setTargetHosts(String v){targetHosts=v;}
    public String getCanaryHost(){return canaryHost;} public void setCanaryHost(String v){canaryHost=v;}
    public Instant getCanaryStartedAt(){return canaryStartedAt;} public void setCanaryStartedAt(Instant v){canaryStartedAt=v;}
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
