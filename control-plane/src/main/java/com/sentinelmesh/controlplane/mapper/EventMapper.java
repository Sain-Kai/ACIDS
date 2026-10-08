package com.sentinelmesh.controlplane.mapper;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelmesh.controlplane.dto.IncomingEventDTO;
import com.sentinelmesh.controlplane.model.SecurityEvent;
import org.springframework.stereotype.Component;

/** Flattens the nested IncomingEventDTO into the flat SecurityEvent entity. */
@Component
public class EventMapper {

    private final ObjectMapper objectMapper;

    public EventMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public SecurityEvent toEntity(IncomingEventDTO dto) {
        SecurityEvent e = new SecurityEvent();
        e.setEventId(dto.eventId);
        e.setCorrelationId(dto.correlationId);
        e.setTimestamp(dto.timestamp);
        e.setSource(dto.source);
        e.setEventType(dto.eventType);
        e.setSeverityRaw(dto.severityRaw);

        if (dto.host != null) {
            e.setHostname(dto.host.hostname);
            e.setHostIp(dto.host.ip);
            e.setContainerId(dto.host.containerId);
            e.setContainerImage(dto.host.containerImage);
        }
        if (dto.process != null) {
            e.setProcessPid(dto.process.pid);
            e.setProcessPpid(dto.process.ppid);
            e.setProcessExe(dto.process.exe);
            e.setProcessCmdline(dto.process.cmdline);
            e.setProcessUser(dto.process.user);
        }
        if (dto.network != null) {
            e.setNetworkSrcIp(dto.network.srcIp);
            e.setNetworkDstIp(dto.network.dstIp);
            e.setNetworkSrcPort(dto.network.srcPort);
            e.setNetworkDstPort(dto.network.dstPort);
            e.setNetworkProtocol(dto.network.protocol);
        }
        if (dto.file != null) {
            e.setFilePath(dto.file.path);
            e.setFileOperation(dto.file.operation);
        }
        if(dto.tags != null) e.setTagsCsv(String.join(",", dto.tags));
        if (dto.rawPayload != null) {
            try {
                e.setRawPayloadJson(objectMapper.writeValueAsString(dto.rawPayload));
            } catch (JsonProcessingException ex) {
                e.setRawPayloadJson(null);
            }
        }
        return e;
    }
}
