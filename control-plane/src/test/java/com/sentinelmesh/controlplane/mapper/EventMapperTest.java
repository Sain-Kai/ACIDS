package com.sentinelmesh.controlplane.mapper;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelmesh.controlplane.dto.IncomingEventDTO;
import com.sentinelmesh.controlplane.model.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EventMapperTest {

    private final EventMapper mapper = new EventMapper(new ObjectMapper());

    @Test
    void mapsBasicFieldsAndNestedProcessNetworkFile() {
        IncomingEventDTO dto = new IncomingEventDTO();
        dto.eventId = "evt-123";
        dto.correlationId = "corr-1";
        dto.timestamp = Instant.parse("2026-01-01T00:00:00Z");
        dto.source = "falco";
        dto.eventType = "process_exec";
        dto.severityRaw = "critical";

        dto.host = new IncomingEventDTO.HostDTO();
        dto.host.hostname = "host-a";
        dto.host.ip = "10.0.0.5";

        dto.process = new IncomingEventDTO.ProcessDTO();
        dto.process.pid = 4242;
        dto.process.exe = "/bin/bash";
        dto.process.cmdline = "bash -i";
        dto.process.user = "www-data";

        dto.network = new IncomingEventDTO.NetworkDTO();
        dto.network.srcIp = "10.0.0.5";
        dto.network.dstIp = "169.254.169.254";
        dto.network.dstPort = 80;

        dto.file = new IncomingEventDTO.FileDTO();
        dto.file.path = "/etc/cron.d/x";
        dto.file.operation = "write";

        dto.rawPayload = Map.of("proc.pname", "nginx");

        SecurityEvent entity = mapper.toEntity(dto);

        assertEquals("evt-123", entity.getEventId());
        assertEquals("corr-1", entity.getCorrelationId());
        assertEquals("falco", entity.getSource());
        assertEquals("process_exec", entity.getEventType());
        assertEquals("critical", entity.getSeverityRaw());
        assertEquals("host-a", entity.getHostname());
        assertEquals("10.0.0.5", entity.getHostIp());
        assertEquals(4242, entity.getProcessPid());
        assertEquals("/bin/bash", entity.getProcessExe());
        assertEquals("bash -i", entity.getProcessCmdline());
        assertEquals("www-data", entity.getProcessUser());
        assertEquals("10.0.0.5", entity.getNetworkSrcIp());
        assertEquals("169.254.169.254", entity.getNetworkDstIp());
        assertEquals(80, entity.getNetworkDstPort());
        assertEquals("/etc/cron.d/x", entity.getFilePath());
        assertEquals("write", entity.getFileOperation());
        assertTrue(entity.getRawPayloadJson().contains("proc.pname"));
    }

    @Test
    void handlesNullNestedObjectsWithoutThrowing() {
        IncomingEventDTO dto = new IncomingEventDTO();
        dto.eventId = "evt-minimal";
        // host/process/network/file/rawPayload all left null -- the
        // mapper must not NPE on any of these.

        SecurityEvent entity = mapper.toEntity(dto);

        assertEquals("evt-minimal", entity.getEventId());
        assertNull(entity.getHostname());
        assertNull(entity.getHostIp());
        assertNull(entity.getProcessExe());
        assertNull(entity.getProcessPid());
        assertNull(entity.getNetworkDstIp());
        assertNull(entity.getFilePath());
        assertNull(entity.getRawPayloadJson());
    }
}
