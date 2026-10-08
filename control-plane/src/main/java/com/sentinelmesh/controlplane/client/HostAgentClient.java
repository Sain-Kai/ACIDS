package com.sentinelmesh.controlplane.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

@Component
public class HostAgentClient {
    private static final Logger log = LoggerFactory.getLogger(HostAgentClient.class);
    private final HostRegistry registry;
    private final String apiKey;
    private final Duration timeout = Duration.ofSeconds(5);
    private final RestClient.Builder builder;

    public HostAgentClient(int port, String apiKey) {
        this(new HostRegistry("localhost=http://localhost:" + port, port, true), apiKey);
    }

    @Autowired
    public HostAgentClient(HostRegistry registry,
                           @Value("${sentinelmesh.security.host-agent-api-key}") String apiKey) {
        this.registry = registry; this.apiKey = apiKey;
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
        JdkClientHttpRequestFactory rf = new JdkClientHttpRequestFactory(client); rf.setReadTimeout(timeout);
        this.builder = RestClient.builder().requestFactory(rf).defaultHeader("X-SentinelMesh-Api-Key", apiKey);
    }

    private RestClient clientFor(String hostname) {
        String endpoint = registry.endpointFor(hostname);
        if (endpoint == null) throw new HostAgentUnavailable("host is not registered: " + hostname);
        return builder.baseUrl(endpoint).build();
    }
    public List<String> hosts() { return registry.hosts(); }
    public boolean registered(String hostname) { return registry.endpointFor(hostname) != null; }

    /** Return the identity the protected host-agent itself reports. This is used
     * by missed-compromise discovery to bind evidence to the actual registered
     * host rather than trusting attacker-supplied host metadata. */
    public Identity identity(String hostname) {
        try {
            Map<?, ?> m = clientFor(hostname).get().uri("/v1/identity").retrieve().body(Map.class);
            if (m == null) return new Identity(hostname, "");
            String reportedHost = m.get("hostname") == null ? hostname : String.valueOf(m.get("hostname"));
            String ip = m.get("ip") == null ? "" : String.valueOf(m.get("ip"));
            return new Identity(reportedHost, ip);
        } catch (RestClientException | HostAgentUnavailable e) {
            log.warn("host-agent identity failed host={} err={}", hostname, e.getMessage());
            return new Identity(hostname, "");
        }
    }

    public record KillTarget(Integer pid, String exe) {}
    public record KillResult(int attempted, int killed, int skipped) { public static final KillResult EMPTY = new KillResult(0,0,0); }
    public record KillOperationResult(KillResult result, boolean reachable, boolean success, String message) {}
    public record QuarantineResult(String path, boolean reachable, boolean success, String message) {}
    public record Identity(String hostname, String ip) {}
    public record OperationResult(boolean success, boolean reachable, String message) {}
    public record ScanResult(boolean reachable, boolean success, List<String> findings, String message) {}

    public KillResult kill(String hostname, List<KillTarget> targets) { return killDetailed(hostname, targets).result(); }
    public KillOperationResult killDetailed(String hostname, List<KillTarget> targets) {
        if (targets.isEmpty()) return new KillOperationResult(KillResult.EMPTY,true,true,"no targets");
        try {
            Map<?,?> m = clientFor(hostname).post().uri("/v1/kill").body(Map.of("targets",targets)).retrieve().body(Map.class);
            return new KillOperationResult(toKillResult(m),true,true,"ok");
        } catch (RestClientException | HostAgentUnavailable e) {
            log.warn("host-agent kill failed host={} err={}",hostname,e.getMessage());
            return new KillOperationResult(KillResult.EMPTY,!(e instanceof HostAgentUnavailable),false,e.getMessage());
        }
    }
    public boolean lockAccount(String hostname,String username) { return post(hostname,"/v1/account/lock",Map.of("username",username)).success(); }
    public String quarantine(String hostname,String path,String eventId) { return quarantineDetailed(hostname,path,eventId).path(); }
    public QuarantineResult quarantineDetailed(String hostname,String path,String eventId) {
        try { Map<?,?> m=clientFor(hostname).post().uri("/v1/quarantine").body(Map.of("path",path,"event_id",eventId)).retrieve().body(Map.class); String q=m==null||m.get("quarantine_path")==null?"":String.valueOf(m.get("quarantine_path")); boolean ok=!q.isBlank(); return new QuarantineResult(q,true,ok,ok?"ok":"empty response"); }
        catch (RestClientException|HostAgentUnavailable e){ log.warn("host-agent quarantine failed host={} err={}",hostname,e.getMessage()); return new QuarantineResult("",!(e instanceof HostAgentUnavailable),false,e.getMessage()); }
    }
    public OperationResult isolateDetailed(String hostname,String ip){ return post(hostname,"/v1/network/isolate",Map.of("ip",ip)); }
    public OperationResult liftDetailed(String hostname,String ip){ return post(hostname,"/v1/network/lift",Map.of("ip",ip)); }
    public boolean isolate(String hostname,String ip){ return isolateDetailed(hostname,ip).success(); }
    public boolean lift(String hostname,String ip){ return liftDetailed(hostname,ip).success(); }
    public String snapshotId(String hostname){
        try {
            Map<?,?> m = clientFor(hostname).post().uri("/v1/snapshot").body(Map.of()).retrieve().body(Map.class);
            if (m == null) return "";
            Object complete = m.get("complete");
            if (Boolean.FALSE.equals(complete)) return "";
            Object id = m.get("snapshot_id");
            return id == null ? "" : String.valueOf(id);
        } catch (RestClientException | HostAgentUnavailable e) {
            log.warn("host-agent snapshot failed host={} err={}", hostname, e.getMessage());
            return "";
        }
    }
    public boolean snapshot(String hostname){ return !snapshotId(hostname).isBlank(); }

    public OperationResult restoreDetailed(String hostname,String path,Instant before){
        try { Map<?,?> m=clientFor(hostname).post().uri("/v1/restore").body(Map.of("path",path,"before",before.toString())).retrieve().body(Map.class); boolean ok=m!=null && Boolean.TRUE.equals(m.get("restored")); return new OperationResult(ok,true,ok?"restored":"no snapshot/path available"); }
        catch (RestClientException|HostAgentUnavailable e){ log.warn("host-agent restore failed host={} err={}",hostname,e.getMessage()); return new OperationResult(false,!(e instanceof HostAgentUnavailable),e.getMessage()); }
    }
    public boolean restore(String hostname,String path,Instant before){return restoreDetailed(hostname,path,before).success();}

    @SuppressWarnings("unchecked")
    public ScanResult persistenceScanDetailed(String hostname,Instant since){
        try {
            Map<String,Object> m=clientFor(hostname).post().uri("/v1/persistence-scan").body(Map.of("since",since.toString())).retrieve().body(Map.class);
            if(m==null) return new ScanResult(true,false,List.of(),"empty response");
            Object f=m.get("findings");
            return new ScanResult(true,true,f instanceof List?(List<String>)f:List.of(),"ok");
        }
        catch(RestClientException|HostAgentUnavailable e){ log.warn("host-agent persistence scan failed host={} err={}",hostname,e.getMessage()); return new ScanResult(!(e instanceof HostAgentUnavailable),false,List.of(),e.getMessage()); }
    }
    public List<String> persistenceScan(String hostname,Instant since){return persistenceScanDetailed(hostname,since).findings();}

    public String sandboxAnalyze(String hostname,String quarantinePath){
        try { Map<?,?> m=clientFor(hostname).post().uri("/v1/sandbox-analyze").body(Map.of("quarantine_path",quarantinePath)).retrieve().body(Map.class); return m==null?"":m.get("report")==null?"":String.valueOf(m.get("report")); }
        catch(RestClientException|HostAgentUnavailable e){log.warn("host-agent sandbox failed host={} err={}",hostname,e.getMessage());return "";}
    }

    public record PolicyStatus(boolean present, long version, boolean reachable, boolean success, String message) {}

    public PolicyStatus policyStatus(String hostname) {
        try {
            Map<?,?> m = clientFor(hostname).get().uri("/v1/policy/status").retrieve().body(Map.class);
            if (m == null) return new PolicyStatus(false, 0, true, false, "empty response");
            boolean present = Boolean.TRUE.equals(m.get("present"));
            Object v = m.get("version");
            long version = v instanceof Number n ? n.longValue() : 0L;
            return new PolicyStatus(present, version, true, true, "ok");
        } catch (RestClientException | HostAgentUnavailable e) {
            log.warn("host-agent policy status failed host={} err={}", hostname, e.getMessage());
            return new PolicyStatus(false, 0, !(e instanceof HostAgentUnavailable), false, e.getMessage());
        }
    }

    public OperationResult applyPolicy(String hostname, Map<String,Object> signed){ return post(hostname,"/v1/policy/apply",signed); }
    public OperationResult rollbackPolicy(String hostname, Map<String,Object> signed){ return post(hostname,"/v1/policy/rollback",signed); }
    public OperationResult health(String hostname){
        try { clientFor(hostname).get().uri("/healthz").retrieve().toBodilessEntity(); return new OperationResult(true,true,"ok"); }
        catch(RestClientException|HostAgentUnavailable e){ return new OperationResult(false,!(e instanceof HostAgentUnavailable),e.getMessage()); }
    }

    private OperationResult post(String hostname,String uri,Map<String,Object> body){
        try { clientFor(hostname).post().uri(uri).body(body).retrieve().toBodilessEntity(); return new OperationResult(true,true,"ok"); }
        catch(RestClientException|HostAgentUnavailable e){ return new OperationResult(false,!(e instanceof HostAgentUnavailable),e.getMessage()); }
    }
    private static KillResult toKillResult(Map<?,?> m){
        if(m==null)return KillResult.EMPTY;
        return new KillResult(intValue(m.get("attempted")),intValue(m.get("killed")),intValue(m.get("skipped")));
    }
    private static int intValue(Object o){return o instanceof Number n?n.intValue():0;}
    static final class HostAgentUnavailable extends RuntimeException { HostAgentUnavailable(String m){super(m);} }
}
