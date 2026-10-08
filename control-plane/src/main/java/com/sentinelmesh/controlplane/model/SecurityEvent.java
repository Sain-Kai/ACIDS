package com.sentinelmesh.controlplane.model;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * Mirrors common/schema/event.schema.json. Persisted as part of an
 * Incident so the full normalized event is available for RCA later.
 */
@Entity
@Table(name = "security_events")
public class SecurityEvent {

    @Id
    private String eventId;

    private String correlationId;
    private Instant timestamp;
    private String source;
    private String hostname;
    private String hostIp;
    private String eventType;
    private String severityRaw;

    private Integer processPid;
    private Integer processPpid;
    @Column(length = 4000)
    private String processCmdline;
    private String processExe;
    private String processUser;

    private String networkSrcIp;
    private String networkDstIp;
    private Integer networkSrcPort;
    private Integer networkDstPort;
    private String networkProtocol;

    private String filePath;
    private String fileOperation;
    @Column(length = 4000) private String tagsCsv;
    private String containerId;
    private String containerImage;

    @Lob
    private String rawPayloadJson;

    // getters/setters

    public String getEventId() { return eventId; }
    public void setEventId(String eventId) { this.eventId = eventId; }
    public String getCorrelationId() { return correlationId; }
    public void setCorrelationId(String correlationId) { this.correlationId = correlationId; }
    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }
    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }
    public String getHostname() { return hostname; }
    public void setHostname(String hostname) { this.hostname = hostname; }
    public String getHostIp() { return hostIp; }
    public void setHostIp(String hostIp) { this.hostIp = hostIp; }
    public String getEventType() { return eventType; }
    public void setEventType(String eventType) { this.eventType = eventType; }
    public String getSeverityRaw() { return severityRaw; }
    public void setSeverityRaw(String severityRaw) { this.severityRaw = severityRaw; }
    public Integer getProcessPid() { return processPid; }
    public void setProcessPid(Integer processPid) { this.processPid = processPid; }
    public Integer getProcessPpid(){return processPpid;} public void setProcessPpid(Integer v){processPpid=v;}
    public String getProcessCmdline() { return processCmdline; }
    public void setProcessCmdline(String processCmdline) { this.processCmdline = processCmdline; }
    public String getProcessExe() { return processExe; }
    public void setProcessExe(String processExe) { this.processExe = processExe; }
    public String getProcessUser() { return processUser; }
    public void setProcessUser(String processUser) { this.processUser = processUser; }
    public String getNetworkSrcIp() { return networkSrcIp; }
    public void setNetworkSrcIp(String networkSrcIp) { this.networkSrcIp = networkSrcIp; }
    public String getNetworkDstIp() { return networkDstIp; }
    public void setNetworkDstIp(String networkDstIp) { this.networkDstIp = networkDstIp; }
    public Integer getNetworkSrcPort(){return networkSrcPort;} public void setNetworkSrcPort(Integer v){networkSrcPort=v;}
    public Integer getNetworkDstPort() { return networkDstPort; }
    public void setNetworkDstPort(Integer networkDstPort) { this.networkDstPort = networkDstPort; }
    public String getNetworkProtocol(){return networkProtocol;} public void setNetworkProtocol(String v){networkProtocol=v;}
    public String getFilePath() { return filePath; }
    public void setFilePath(String filePath) { this.filePath = filePath; }
    public String getFileOperation() { return fileOperation; }
    public void setFileOperation(String fileOperation) { this.fileOperation = fileOperation; }
    public String getTagsCsv(){return tagsCsv;} public void setTagsCsv(String v){tagsCsv=v;}
    public String getContainerId(){return containerId;} public void setContainerId(String v){containerId=v;}
    public String getContainerImage(){return containerImage;} public void setContainerImage(String v){containerImage=v;}
    public String getRawPayloadJson() { return rawPayloadJson; }
    public void setRawPayloadJson(String rawPayloadJson) { this.rawPayloadJson = rawPayloadJson; }
}
