package com.sentinelmesh.controlplane.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Mirrors detection-engine's internal/types.Event (Go) as marshaled to
 * JSON -- field names here must match the `json:"..."` tags in types.go
 * exactly. This is the wire contract; common/schema/event.schema.json is
 * the source of truth both sides are written against.
 */
public class IncomingEventDTO {

    @JsonProperty("event_id")
    @NotBlank(message = "event_id is required")
    public String eventId;

    @JsonProperty("correlation_id")
    public String correlationId;

    public Instant timestamp;
    public String source;
    public HostDTO host;

    @JsonProperty("event_type")
    public String eventType;

    public ProcessDTO process;
    public NetworkDTO network;
    public FileDTO file;
    public String syscall;

    @JsonProperty("severity_raw")
    public String severityRaw;

    public List<String> tags;

    @JsonProperty("raw_payload")
    public Map<String, Object> rawPayload;

    public static class HostDTO {
        public String hostname;
        public String ip;
        @JsonProperty("container_id") public String containerId;
        @JsonProperty("container_image") public String containerImage;
    }

    public static class ProcessDTO {
        public Integer pid;
        public Integer ppid;
        public String exe;
        public String cmdline;
        public String user;
    }

    public static class NetworkDTO {
        @JsonProperty("src_ip") public String srcIp;
        @JsonProperty("dst_ip") public String dstIp;
        @JsonProperty("src_port") public Integer srcPort;
        @JsonProperty("dst_port") public Integer dstPort;
        public String protocol;
    }

    public static class FileDTO {
        public String path;
        public String operation;
    }
}
