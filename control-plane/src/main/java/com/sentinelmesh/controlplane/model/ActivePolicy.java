package com.sentinelmesh.controlplane.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import java.time.Instant;

@Entity
public class ActivePolicy {
    @Id private String id = "active";
    private long version;
    private Instant updatedAt = Instant.now();
    @jakarta.persistence.Lob private String payload;
    private String signature;
    public String getId(){return id;} public long getVersion(){return version;} public void setVersion(long v){version=v;}
    public Instant getUpdatedAt(){return updatedAt;} public void setUpdatedAt(Instant v){updatedAt=v;}
    public String getPayload(){return payload;} public void setPayload(String v){payload=v;}
    public String getSignature(){return signature;} public void setSignature(String v){signature=v;}
}
