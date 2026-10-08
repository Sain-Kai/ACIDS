package com.sentinelmesh.controlplane.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelmesh.controlplane.audit.AuditLogger;
import com.sentinelmesh.controlplane.client.HostAgentClient;
import com.sentinelmesh.controlplane.model.GuardedDeployment;
import com.sentinelmesh.controlplane.model.Incident;
import com.sentinelmesh.controlplane.repository.IncidentRepository;
import com.sentinelmesh.controlplane.repository.GuardedDeploymentRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;

@Service
public class GuardedDeployService {
    private final GuardedDeploymentRepository repository; private final AuditLogger audit; private final HostAgentClient agent; private final PolicyService policies; private final ObjectMapper mapper; private final IncidentRepository incidents;
    public GuardedDeployService(GuardedDeploymentRepository r,AuditLogger a,HostAgentClient agent,PolicyService policies,ObjectMapper mapper,IncidentRepository incidents){this.repository=r;this.audit=a;this.agent=agent;this.policies=policies;this.mapper=mapper;this.incidents=incidents;}

    public synchronized GuardedDeployment stageAndCanary(Map<String,Object> payload){
        if(!Boolean.TRUE.equals(payload.get("approved"))) throw new IllegalArgumentException("guarded deployment requires approved=true from Security Judge");
        Object patch=payload.get("patch_manifest"); if(patch==null) throw new IllegalArgumentException("patch_manifest is required");
        String incidentId=String.valueOf(payload.getOrDefault("incident_id","")).trim();
        if(incidentId.isBlank() || "null".equalsIgnoreCase(incidentId)) throw new IllegalArgumentException("incident_id is required");
        if (!repository.findByStage(GuardedDeployment.Stage.CANARY).isEmpty()) {
            throw new IllegalStateException("another guarded deployment is already in CANARY; refusing concurrent policy rollout");
        }
        Incident incident=incidents.findById(incidentId).orElseThrow(() -> new IllegalArgumentException("unknown incident: "+incidentId));
        if(incident.getStatus()!=Incident.Status.CONTAINED && incident.getStatus()!=Incident.Status.RECLAIM_COMPLETE && incident.getStatus()!=Incident.Status.RESOLVED) {
            throw new IllegalStateException("incident is not in a safe deployment state: "+incident.getStatus());
        }
        List<String> hosts=agent.hosts(); if(hosts.isEmpty()) throw new IllegalStateException("no registered host-agents available for deployment");
        Map<String,Object> signed=policies.buildFromPatch(patch); Map<String,Object> previous=policies.current();
        long candidateVersion=((Number)signed.get("version")).longValue();
        long previousVersion=((Number)previous.getOrDefault("version",1)).longValue();
        if(candidateVersion<=previousVersion) throw new IllegalStateException("candidate policy version must be newer than active policy");
        for(String host:hosts){
            HostAgentClient.PolicyStatus st=agent.policyStatus(host);
            if(!st.success()) throw new IllegalStateException("cannot establish policy state for host "+host+": "+st.message());
            if(st.version()>candidateVersion) throw new IllegalStateException("host "+host+" is ahead of candidate policy version (host="+st.version()+", candidate="+candidateVersion+")");
        }
        GuardedDeployment d=new GuardedDeployment();d.setIncidentId(incidentId);d.setMatchedRules(String.valueOf(payload.getOrDefault("matched_rules","")));d.setProposedChange(String.valueOf(payload.getOrDefault("proposed_change",patch)));d.setJudgeRationale(String.valueOf(payload.getOrDefault("judge_rationale","")));
        d.setSignedPolicy(write(signed)); d.setPreviousPolicy(write(previous)); d.setTargetHosts(String.join(",",hosts)); d.setCanaryHost(hosts.get(0)); d.setStage(GuardedDeployment.Stage.STAGED); repository.save(d);
        audit.log(d.getIncidentId(),"DEPLOY_STAGED","deployment="+d.getDeploymentId()+" targets="+hosts.size());
        HostAgentClient.OperationResult canary=agent.applyPolicy(hosts.get(0),signed);
        if(!canary.success()){
            Map<String,Object> rollback=policies.buildRollbackFrom(previous);
            HostAgentClient.OperationResult rb=agent.rollbackPolicy(hosts.get(0),rollback);
            boolean rollbackOk=rb != null && rb.success();
            d.setStage(rollbackOk?GuardedDeployment.Stage.ROLLED_BACK:GuardedDeployment.Stage.FAILED_NEEDS_REVIEW);
            repository.save(d);
            audit.log(d.getIncidentId(),rollbackOk?"DEPLOY_CANARY_FAILED":"DEPLOY_CANARY_ROLLBACK_FAILED","deployment="+d.getDeploymentId()+" host="+hosts.get(0)+" err="+canary.message()+" rollbackOk="+rollbackOk);
            return d;
        }
        d.setStage(GuardedDeployment.Stage.CANARY);d.setCanaryStartedAt(Instant.now());repository.save(d);audit.log(d.getIncidentId(),"DEPLOY_CANARY","deployment="+d.getDeploymentId()+" host="+hosts.get(0));return d;
    }

    public synchronized GuardedDeployment promote(String id){
        GuardedDeployment d=find(id); if(d.getStage()!=GuardedDeployment.Stage.CANARY) throw new IllegalStateException("deployment is not in CANARY stage");
        Map<String,Object> signed=read(d.getSignedPolicy()), previous=read(d.getPreviousPolicy());
        // Host agents accept only strictly increasing policy versions. Build the
        // rollback image up front so any partially-applied rollout can be
        // reversed without sending the stale previous version.
        Map<String,Object> rollbackPolicy = policies.buildRollbackFrom(previous);
        List<String> applied=new ArrayList<>();
        for(String host:split(d.getTargetHosts())){
            HostAgentClient.OperationResult r=agent.applyPolicy(host,signed);
            if(!r.success()){
                boolean rollbackOk=true;
                for(String a:applied){
                    HostAgentClient.OperationResult rb=agent.rollbackPolicy(a,rollbackPolicy);
                    rollbackOk &= rb != null && rb.success();
                }
                if (rollbackOk && !applied.isEmpty()) {
                    try { policies.activateRollback(rollbackPolicy); } catch (RuntimeException e) { rollbackOk=false; }
                }
                d.setStage(rollbackOk?GuardedDeployment.Stage.ROLLED_BACK:GuardedDeployment.Stage.FAILED_NEEDS_REVIEW);
                repository.save(d);
                audit.log(d.getIncidentId(),rollbackOk?"DEPLOY_PROMOTE_FAILED":"DEPLOY_ROLLBACK_FAILED","deployment="+id+" host="+host+" err="+r.message()+" rollbackOk="+rollbackOk);
                return d;
            }
            applied.add(host);
        }
        try {
            policies.promote(signed);
        } catch (RuntimeException dbFailure) {
            boolean rollbackOk = true;
            for (String host : applied) {
                HostAgentClient.OperationResult rb = agent.rollbackPolicy(host, rollbackPolicy);
                rollbackOk &= rb != null && rb.success();
            }
            if (rollbackOk) {
                try { policies.activateRollback(rollbackPolicy); } catch (RuntimeException e) { rollbackOk=false; }
            }
            d.setStage(rollbackOk ? GuardedDeployment.Stage.ROLLED_BACK : GuardedDeployment.Stage.FAILED_NEEDS_REVIEW);
            repository.save(d);
            audit.log(d.getIncidentId(), rollbackOk ? "DEPLOY_DB_COMMIT_FAILED" : "DEPLOY_DB_COMMIT_AND_ROLLBACK_FAILED",
                    "deployment="+id+" err="+dbFailure.getMessage()+" rollbackOk="+rollbackOk);
            return d;
        }
        d.setStage(GuardedDeployment.Stage.PROMOTED);repository.save(d);audit.log(d.getIncidentId(),"DEPLOY_PROMOTED","deployment="+id+" hosts="+applied.size());return d;
    }

    public synchronized GuardedDeployment rollback(String id,String reason){
        GuardedDeployment d=find(id);
        if (d.getStage() == GuardedDeployment.Stage.STAGED || d.getStage() == GuardedDeployment.Stage.ROLLED_BACK) {
            return d;
        }
        if (d.getStage() != GuardedDeployment.Stage.CANARY && d.getStage() != GuardedDeployment.Stage.PROMOTED) {
            throw new IllegalStateException("deployment is not safely rollbackable from stage " + d.getStage());
        }
        Map<String,Object> previous=read(d.getPreviousPolicy());
        boolean allOk=true;
        Map<String,Object> rollbackPolicy=null;
        if(d.getStage()==GuardedDeployment.Stage.CANARY || d.getStage()==GuardedDeployment.Stage.PROMOTED){
            // The candidate policy may already have reached at least the canary
            // host. Rollback must therefore be a NEWER version, even when the
            // active control-plane policy itself was never promoted.
            rollbackPolicy=policies.buildRollbackFrom(previous);
        }
        for(String host:split(d.getTargetHosts())) {
            HostAgentClient.OperationResult r=agent.rollbackPolicy(host, rollbackPolicy==null?previous:rollbackPolicy);
            allOk &= r != null && r.success();
        }
        if(allOk && rollbackPolicy!=null) {
            try { policies.activateRollback(rollbackPolicy); } catch (RuntimeException e) { allOk=false; }
        }
        d.setStage(allOk?GuardedDeployment.Stage.ROLLED_BACK:GuardedDeployment.Stage.FAILED_NEEDS_REVIEW);
        repository.save(d);
        audit.log(d.getIncidentId(),allOk?"DEPLOY_ROLLED_BACK":"DEPLOY_ROLLBACK_FAILED","deployment="+id+" reason="+reason+" allHostsRestored="+allOk);
        return d;
    }
    private GuardedDeployment find(String id){return repository.findById(id).orElseThrow(()->new IllegalArgumentException("no such deployment: "+id));}
    private static List<String> split(String s){if(s==null||s.isBlank())return List.of();return Arrays.stream(s.split(",")).map(String::trim).filter(x->!x.isBlank()).toList();}
    private String write(Map<String,Object> m){try{return mapper.writeValueAsString(m);}catch(Exception e){throw new IllegalStateException(e);}}
    @SuppressWarnings("unchecked") private Map<String,Object> read(String s){try{return mapper.readValue(s,Map.class);}catch(Exception e){throw new IllegalStateException(e);}}
}
