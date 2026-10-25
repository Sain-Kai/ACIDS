package com.sentinelmesh.controlplane.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelmesh.controlplane.model.ActivePolicy;
import com.sentinelmesh.controlplane.repository.ActivePolicyRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.util.*;

@Service
public class PolicyService {
    private final ActivePolicyRepository repo; private final ObjectMapper mapper; private final String key;
    public PolicyService(ActivePolicyRepository repo,ObjectMapper mapper,@Value("${sentinelmesh.policy-signing-key}") String key){this.repo=repo;this.mapper=mapper;this.key=key;}
    public synchronized Map<String,Object> current(){
        ActivePolicy p=repo.findById("active").orElseGet(()->init());
        return Map.of("payload",p.getPayload(),"signature",p.getSignature());
    }
    public synchronized Map<String,Object> buildFromPatch(Object patchObj){
        try{
            JsonNode root=patchObj instanceof String ? mapper.readTree((String)patchObj) : mapper.valueToTree(patchObj);
            if(!root.has("patches")||!root.get("patches").isArray()||root.get("patches").isEmpty()) throw new IllegalArgumentException("patch_manifest.patches must be a non-empty array");
            ActivePolicy current=repo.findById("active").orElseGet(()->init());
            JsonNode doc=mapper.readTree(current.getPayload());
            long version=doc.path("version").asLong(1)+1;
            Map<String,Object> out=new LinkedHashMap<>();
            out.put("version",version); out.put("generated_at",Instant.now().toString());
            List<String> blocked=new ArrayList<>(); doc.path("blocked_ips").forEach(n->blocked.add(n.asText()));
            List<String> patterns=new ArrayList<>(); doc.path("extra_command_patterns").forEach(n->patterns.add(n.asText()));
            double contain=doc.path("contain_threshold").asDouble(0.60), block=doc.path("block_threshold").asDouble(0.85), reclaim=doc.path("reclaim_threshold").asDouble(0.95);
            for(JsonNode patch:root.get("patches")){
                String kind=patch.path("kind").asText("").toUpperCase(Locale.ROOT); String value=patch.path("value").asText("");
                switch(kind){
                    case "BLOCK_IP" -> { if(!safeIp(value)) throw new IllegalArgumentException("invalid or local BLOCK_IP"); if(!blocked.contains(value))blocked.add(value); }
                    case "COMMAND_PATTERN" -> { if(value.isBlank()||value.length()>200||value.indexOf('\0')>=0)throw new IllegalArgumentException("invalid COMMAND_PATTERN"); if(!patterns.contains(value))patterns.add(value); }
                    case "CONTAIN_THRESHOLD", "BLOCK_THRESHOLD", "RECLAIM_THRESHOLD" -> throw new IllegalArgumentException("threshold changes require explicit human security-automation workflow");
                    default -> throw new IllegalArgumentException("unsupported patch kind: "+kind);
                }
            }
            if(!(contain<block&&block<reclaim))throw new IllegalArgumentException("threshold order must be contain < block < reclaim");
            out.put("blocked_ips",blocked); out.put("extra_command_patterns",patterns); out.put("contain_threshold",contain); out.put("block_threshold",block); out.put("reclaim_threshold",reclaim);
            String payload=mapper.writeValueAsString(out); String sig=hmac(payload);
            return Map.of("payload",payload,"signature",sig,"version",version);
        }catch(Exception e){throw new IllegalArgumentException("invalid defensive patch manifest: "+e.getMessage(),e);}
    }
    public synchronized void promote(Map<String,Object> signed){
        String payload=String.valueOf(signed.get("payload")), signature=String.valueOf(signed.get("signature")); verify(payload,signature);
        try{
            JsonNode n=mapper.readTree(payload);
            ActivePolicy current=repo.findById("active").orElseGet(()->init());
            if(n.path("version").asLong()<=current.getVersion()) throw new IllegalArgumentException("promoted policy version must increase");
            ActivePolicy p=repo.findById("active").orElse(new ActivePolicy());
            p.setVersion(n.path("version").asLong());p.setPayload(payload);p.setSignature(signature);p.setUpdatedAt(Instant.now());repo.save(p);
        }catch(Exception e){throw new IllegalArgumentException("invalid promoted policy: "+e.getMessage(),e);}
    }

    /**
     * Creates a rollback image that is semantically based on an older policy
     * but receives a NEWER monotonically increasing version. The detector
     * activates only increasing versions, so rollback must not reuse the old
     * version number or runtime rollback would be silently ignored.
     */
    public synchronized Map<String,Object> buildRollbackFrom(Map<String,Object> signedPrevious){
        String payload=String.valueOf(signedPrevious.get("payload")), signature=String.valueOf(signedPrevious.get("signature")); verify(payload,signature);
        try{
            JsonNode prev=mapper.readTree(payload);
            ActivePolicy current=repo.findById("active").orElseGet(()->init());
            long version=Math.max(current.getVersion()+1, prev.path("version").asLong(0)+1);
            Map<String,Object> out=new LinkedHashMap<>();
            prev.fields().forEachRemaining(e -> out.put(e.getKey(), mapper.convertValue(e.getValue(), Object.class)));
            out.put("version",version);
            out.put("generated_at",Instant.now().toString());
            String newPayload=mapper.writeValueAsString(out);
            return Map.of("payload",newPayload,"signature",hmac(newPayload),"version",version);
        }catch(Exception e){throw new IllegalArgumentException("invalid rollback source: "+e.getMessage(),e);}
    }

    public synchronized void activateRollback(Map<String,Object> signed){
        String payload=String.valueOf(signed.get("payload")), signature=String.valueOf(signed.get("signature")); verify(payload,signature);
        try{
            JsonNode n=mapper.readTree(payload);
            ActivePolicy current=repo.findById("active").orElseGet(()->init());
            if(n.path("version").asLong()<=current.getVersion()) throw new IllegalArgumentException("rollback policy version must increase");
            ActivePolicy p=current;
            p.setVersion(n.path("version").asLong());p.setPayload(payload);p.setSignature(signature);p.setUpdatedAt(Instant.now());repo.save(p);
        }catch(Exception e){throw new IllegalArgumentException("invalid rollback policy: "+e.getMessage(),e);}
    }
    private ActivePolicy init(){
        try{Map<String,Object> base=new LinkedHashMap<>();base.put("version",1L);base.put("generated_at",Instant.now().toString());base.put("blocked_ips",List.of());base.put("extra_command_patterns",List.of());base.put("contain_threshold",0.60);base.put("block_threshold",0.85);base.put("reclaim_threshold",0.95);String payload=mapper.writeValueAsString(base);ActivePolicy p=new ActivePolicy();p.setVersion(1);p.setPayload(payload);p.setSignature(hmac(payload));return repo.save(p);}catch(Exception e){throw new IllegalStateException(e);}
    }
    private void verify(String payload,String sig){if(!MessageDigestIsEqual(hmac(payload),sig))throw new IllegalArgumentException("invalid policy signature");}
    private String hmac(String payload){try{Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(key.getBytes(java.nio.charset.StandardCharsets.UTF_8),"HmacSHA256"));byte[] b=mac.doFinal(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format("%02x",x));return s.toString();}catch(Exception e){throw new IllegalStateException(e);}}
    private static boolean MessageDigestIsEqual(String a,String b){return java.security.MessageDigest.isEqual(a.getBytes(java.nio.charset.StandardCharsets.US_ASCII),b.getBytes(java.nio.charset.StandardCharsets.US_ASCII));}
    private static double threshold(String s,double min,double max){double v=Double.parseDouble(s);if(!Double.isFinite(v)||v<min||v>max)throw new IllegalArgumentException("threshold out of range");return v;}
    private static boolean safeIp(String v){
        String value=v==null?"":v.trim();
        if(!value.matches("(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}")) return false;
        String[] parts=value.split("\\.");
        int first=Integer.parseInt(parts[0]);
        return first!=0 && first!=127 && first!=224 && first<240 && !(first==169 && Integer.parseInt(parts[1])==254);
    }
}
