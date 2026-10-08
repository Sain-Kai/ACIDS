package com.sentinelmesh.controlplane.model;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "incidents")
public class Incident {

    public enum Status {
        DETECTED,
        CONTAINED,
        RECLAIM_IN_PROGRESS,
        RECLAIM_NEEDS_REVIEW, // verify() found persistence indicators; auto-recover was withheld
        RECLAIM_COMPLETE,
        RESOLVED
    }

    @Id
    private String incidentId = UUID.randomUUID().toString();

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "event_id")
    private SecurityEvent event;

    private double verdictScore;

    @Column(length = 2000)
    private String matchedRules; // comma-separated rule names

    private String actionTaken;

    @Column(length = 2000)
    private String actionError;

    private String quarantinePath;

    @Enumerated(EnumType.STRING)
    private Status status = Status.DETECTED;

    @Enumerated(EnumType.STRING)
    private ReclaimState reclaimState;

    @Column(unique = true, length = 200)
    private String idempotencyKey;

    private Instant createdAt = Instant.now();
    private Instant updatedAt = Instant.now();

    public String getIncidentId() { return incidentId; }
    public void setIncidentId(String incidentId) { this.incidentId = incidentId; }
    public SecurityEvent getEvent() { return event; }
    public void setEvent(SecurityEvent event) { this.event = event; }
    public double getVerdictScore() { return verdictScore; }
    public void setVerdictScore(double verdictScore) { this.verdictScore = verdictScore; }
    public String getMatchedRules() { return matchedRules; }
    public void setMatchedRules(String matchedRules) { this.matchedRules = matchedRules; }
    public String getActionTaken() { return actionTaken; }
    public void setActionTaken(String actionTaken) { this.actionTaken = actionTaken; }
    public String getActionError() { return actionError; }
    public void setActionError(String actionError) { this.actionError = actionError; }
    public String getQuarantinePath() { return quarantinePath; }
    public void setQuarantinePath(String quarantinePath) { this.quarantinePath = quarantinePath; }
    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; this.updatedAt = Instant.now(); }
    public ReclaimState getReclaimState() { return reclaimState; }
    public void setReclaimState(ReclaimState reclaimState) { this.reclaimState = reclaimState; }
    public String getIdempotencyKey(){return idempotencyKey;} public void setIdempotencyKey(String v){idempotencyKey=v;}
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
