package com.sentinelmesh.controlplane.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;
import org.springframework.http.HttpHeaders;

/** Provider-neutral credential revocation adapter. Configure a trusted
 * webhook backed by Vault/SSO/IAM in production; blank means local account
 * locking remains the only credential control available on this host. */
@Component
public class CredentialRevocationClient {
    private final RestClient client; private final String url; private final String key;
    public CredentialRevocationClient(@Value("${sentinelmesh.credentials.revocation-webhook:}") String url,
                                      @Value("${sentinelmesh.credentials.revocation-api-key:}") String key){
        this.url=url==null?"":url.trim(); this.key=key==null?"":key;
        HttpClient hc=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
        JdkClientHttpRequestFactory rf=new JdkClientHttpRequestFactory(hc); rf.setReadTimeout(Duration.ofSeconds(5));
        client=RestClient.builder().requestFactory(rf).build();
    }
    public boolean enabled(){return !url.isBlank();}
    public boolean revoke(String incidentId,String hostname,String username,String category){
        if(!enabled()) return true;
        try{client.post().uri(url).headers(h->{if(!key.isBlank())h.set(HttpHeaders.AUTHORIZATION,"Bearer "+key);h.set("Idempotency-Key",incidentId);h.set("X-SentinelMesh-Action","revoke-credentials");}).body(Map.of("incident_id",incidentId,"hostname",hostname,"username",username,"category",category==null?"unknown":category)).retrieve().toBodilessEntity();return true;}
        catch(Exception e){return false;}
    }
}
