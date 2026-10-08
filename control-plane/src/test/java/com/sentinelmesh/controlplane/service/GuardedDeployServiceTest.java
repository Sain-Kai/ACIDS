package com.sentinelmesh.controlplane.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelmesh.controlplane.audit.AuditLogger;
import com.sentinelmesh.controlplane.client.HostAgentClient;
import com.sentinelmesh.controlplane.model.GuardedDeployment;
import com.sentinelmesh.controlplane.model.Incident;
import com.sentinelmesh.controlplane.repository.GuardedDeploymentRepository;
import org.junit.jupiter.api.*;
import org.mockito.*;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class GuardedDeployServiceTest {
    @Mock GuardedDeploymentRepository repository;
    @Mock AuditLogger auditLogger;
    @Mock HostAgentClient agent;
    @Mock PolicyService policies;
    @Mock com.sentinelmesh.controlplane.repository.IncidentRepository incidents;
    private GuardedDeployService service;

    @BeforeEach void setUp(){MockitoAnnotations.openMocks(this); service=new GuardedDeployService(repository,auditLogger,agent,policies,new ObjectMapper(),incidents);}

    @Test void stageAndCanaryActuallyAppliesSignedPolicy(){
        Map<String,Object> signed=Map.of("payload","{}","signature","sig","version",2);
        Incident incident = new Incident(); incident.setIncidentId("inc-1"); incident.setStatus(Incident.Status.CONTAINED);
        when(incidents.findById("inc-1")).thenReturn(Optional.of(incident));
        when(agent.hosts()).thenReturn(List.of("host-a","host-b")); when(policies.buildFromPatch(any())).thenReturn(signed); when(policies.current()).thenReturn(Map.of("payload","{}","signature","old","version",1));
        when(agent.policyStatus(anyString())).thenReturn(new HostAgentClient.PolicyStatus(true,1,true,true,"ok"));
        when(agent.applyPolicy(eq("host-a"),eq(signed))).thenReturn(new HostAgentClient.OperationResult(true,true,"ok"));
        Map<String,Object> payload=new HashMap<>();payload.put("incident_id","inc-1");payload.put("approved",true);payload.put("patch_manifest",Map.of("patches",List.of(Map.of("kind","BLOCK_IP","value","10.0.0.9"))));payload.put("matched_rules","reverse_shell_indicator");
        GuardedDeployment d=service.stageAndCanary(payload);
        assertEquals(GuardedDeployment.Stage.CANARY,d.getStage()); assertEquals("host-a",d.getCanaryHost()); verify(agent).applyPolicy("host-a",signed); verify(repository,atLeast(2)).save(d);
    }

    @Test void rejectsUnapprovedPatch(){assertThrows(IllegalArgumentException.class,()->service.stageAndCanary(Map.of("incident_id","inc","approved",false,"patch_manifest",Map.of("patches",List.of(Map.of("kind","BLOCK_IP","value","10.0.0.9"))))));}

    @Test void promoteRollsBackOnSecondHostFailure(){
        GuardedDeployment d=new GuardedDeployment(); d.setIncidentId("inc"); d.setStage(GuardedDeployment.Stage.CANARY); d.setSignedPolicy("{\"payload\":\"new\",\"signature\":\"s\"}"); d.setPreviousPolicy("{\"payload\":\"old\",\"signature\":\"p\"}"); d.setTargetHosts("host-a,host-b");
        when(repository.findById("d1")).thenReturn(Optional.of(d));
        Map<String,Object> newP=Map.of("payload","new","signature","s");
        Map<String,Object> oldP=Map.of("payload","old","signature","p");
        Map<String,Object> rollbackP=Map.of("payload","old-v2","signature","p2","version",3);
        when(policies.buildRollbackFrom(oldP)).thenReturn(rollbackP);
        when(agent.rollbackPolicy("host-a",rollbackP)).thenReturn(new HostAgentClient.OperationResult(true,true,"rollback-ok"));
        when(agent.applyPolicy("host-a",newP)).thenReturn(new HostAgentClient.OperationResult(true,true,"ok")); when(agent.applyPolicy("host-b",newP)).thenReturn(new HostAgentClient.OperationResult(false,true,"boom"));
        GuardedDeployment r=service.promote("d1"); assertEquals(GuardedDeployment.Stage.ROLLED_BACK,r.getStage()); verify(agent).rollbackPolicy("host-a",rollbackP); verify(policies,never()).promote(newP); verify(policies).activateRollback(rollbackP);
    }
    @Test void stageRejectsSecondConcurrentCanary(){
        GuardedDeployment existing=new GuardedDeployment(); existing.setStage(GuardedDeployment.Stage.CANARY);
        when(repository.findByStage(GuardedDeployment.Stage.CANARY)).thenReturn(List.of(existing));
        Map<String,Object> payload=new HashMap<>(); payload.put("incident_id","inc"); payload.put("approved",true); payload.put("patch_manifest",Map.of("patches",List.of(Map.of("kind","BLOCK_IP","value","10.0.0.9"))));
        assertThrows(IllegalStateException.class,()->service.stageAndCanary(payload));
        verify(agent,never()).applyPolicy(anyString(),anyMap());
    }

    @Test void canaryRollbackUsesNewerVersionAndActivatesIt(){
        GuardedDeployment d=new GuardedDeployment(); d.setIncidentId("inc"); d.setStage(GuardedDeployment.Stage.CANARY); d.setPreviousPolicy("{\"payload\":\"old\",\"signature\":\"p\"}"); d.setTargetHosts("host-a,host-b");
        when(repository.findById("d2")).thenReturn(Optional.of(d));
        Map<String,Object> oldP=Map.of("payload","old","signature","p"); Map<String,Object> rollbackP=Map.of("payload","old-v2","signature","p2","version",4);
        when(policies.buildRollbackFrom(oldP)).thenReturn(rollbackP);
        when(agent.rollbackPolicy("host-a",rollbackP)).thenReturn(new HostAgentClient.OperationResult(true,true,"ok"));
        when(agent.rollbackPolicy("host-b",rollbackP)).thenReturn(new HostAgentClient.OperationResult(true,true,"ok"));
        GuardedDeployment r=service.rollback("d2","test");
        assertEquals(GuardedDeployment.Stage.ROLLED_BACK,r.getStage()); verify(agent).rollbackPolicy("host-a",rollbackP); verify(agent).rollbackPolicy("host-b",rollbackP); verify(policies).activateRollback(rollbackP);
    }

}
