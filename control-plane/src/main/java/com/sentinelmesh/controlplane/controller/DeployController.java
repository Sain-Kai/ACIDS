package com.sentinelmesh.controlplane.controller;

import com.sentinelmesh.controlplane.model.GuardedDeployment;
import com.sentinelmesh.controlplane.service.GuardedDeployService;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;

import java.util.Map;

@RestController
@RequestMapping("/deploy")
public class DeployController {

    private final GuardedDeployService guardedDeployService;

    public DeployController(GuardedDeployService guardedDeployService) {
        this.guardedDeployService = guardedDeployService;
    }

    /** Called by llm-orchestration's orchestrator.py once the Security
     *  Judge approves a patch proposal. */
    @PostMapping("/guarded")
    public GuardedDeployment guardedDeploy(@RequestBody Map<String, Object> payload, Authentication auth) {
        require(auth,"llm-orchestration");
        return guardedDeployService.stageAndCanary(payload);
    }

    @PostMapping("/{id}/promote")
    public GuardedDeployment promote(@PathVariable String id, Authentication auth) {
        require(auth,"security-automation");
        return guardedDeployService.promote(id);
    }

    @PostMapping("/{id}/rollback")
    public GuardedDeployment rollback(@PathVariable String id, @RequestParam(defaultValue = "manual") String reason, Authentication auth) {
        require(auth,"security-automation");
        return guardedDeployService.rollback(id, reason);
    }

    private static void require(Authentication auth,String... allowed){
        String who=auth==null?"":auth.getName(); for(String a:allowed) if(a.equals(who)) return; throw new AccessDeniedException("caller not authorized");
    }
}
