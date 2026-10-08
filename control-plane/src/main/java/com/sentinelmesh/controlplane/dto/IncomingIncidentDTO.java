package com.sentinelmesh.controlplane.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;

/**
 * Mirrors detection-engine's internal/incident.Incident (Go), posted to
 * POST /incidents by incident.Forward().
 */
public class IncomingIncidentDTO {

    @JsonProperty("incident_id")
    public String incidentId;

    @NotNull(message = "event is required")
    @Valid
    public IncomingEventDTO event;

    @NotNull(message = "verdict is required")
    @Valid
    public IncomingVerdictDTO verdict;

    @JsonProperty("action_error")
    public String actionError;

    @JsonProperty("quarantine_path")
    public String quarantinePath;

    @JsonProperty("created_at")
    public Instant createdAt;
}
