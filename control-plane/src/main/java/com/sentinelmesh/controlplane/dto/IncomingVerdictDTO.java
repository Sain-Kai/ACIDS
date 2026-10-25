package com.sentinelmesh.controlplane.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** Mirrors detection-engine's internal/types.Verdict (Go). */
public class IncomingVerdictDTO {
    public double score;

    @JsonProperty("matched_rules")
    public List<String> matchedRules;

    public String action;
}
