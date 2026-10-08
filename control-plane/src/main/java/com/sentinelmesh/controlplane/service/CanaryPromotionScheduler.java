package com.sentinelmesh.controlplane.service;

import com.sentinelmesh.controlplane.audit.AuditLogger;
import com.sentinelmesh.controlplane.model.GuardedDeployment;
import com.sentinelmesh.controlplane.repository.GuardedDeploymentRepository;
import com.sentinelmesh.controlplane.repository.IncidentRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

/**
 * Decides whether a CANARY deployment gets promoted or rolled back once
 * it's baked for canary-bake-minutes.
 *
 * Uses a real, narrow health signal when the deployment is tied to a
 * specific rule (GuardedDeployment.matchedRules, threaded through from
 * the triggering incident): counts how many incidents matching that same
 * rule occurred in an equal-length window immediately BEFORE the
 * deployment, versus DURING its canary bake. If the rate didn't improve
 * (post >= pre, with a real pre-window baseline to compare against),
 * that means the patch evidently didn't reduce recurrence of the exact
 * problem it targeted -- auto-rollback instead of promoting.
 *
 * This deliberately does NOT attempt to judge whether the change is
 * "good for security" in any deeper sense -- only whether the specific
 * recurrence it was meant to address went down. That's a narrow,
 * single-signal proxy, not a real observability/metrics pipeline. When
 * there's no rule to check against (matchedRules blank) or no pre-window
 * incidents to form a baseline from, this falls back to pure
 * an automatic rollback when no measurable baseline exists. This prevents a model-generated
 * policy from reaching the fleet merely because a timer elapsed.
 */
@Component
public class CanaryPromotionScheduler {

    private final GuardedDeploymentRepository deploymentRepository;
    private final IncidentRepository incidentRepository;
    private final GuardedDeployService guardedDeployService;
    private final AuditLogger auditLogger;
    private final Duration bakeTime;

    public CanaryPromotionScheduler(GuardedDeploymentRepository deploymentRepository,
                                     IncidentRepository incidentRepository,
                                     GuardedDeployService guardedDeployService,
                                     AuditLogger auditLogger,
                                     @Value("${sentinelmesh.deploy.canary-bake-minutes}") long bakeMinutes) {
        this.deploymentRepository = deploymentRepository;
        this.incidentRepository = incidentRepository;
        this.guardedDeployService = guardedDeployService;
        this.auditLogger = auditLogger;
        this.bakeTime = Duration.ofMinutes(bakeMinutes);
    }

    @Scheduled(
            fixedRateString = "${sentinelmesh.deploy.canary-check-interval-minutes}",
            timeUnit = TimeUnit.MINUTES
    )
    public void checkCanaries() {
        Instant cutoff = Instant.now().minus(bakeTime);
        for (GuardedDeployment dep : deploymentRepository.findByStage(GuardedDeployment.Stage.CANARY)) {
            if (dep.getUpdatedAt().isBefore(cutoff)) {
                evaluate(dep);
            }
        }
    }

    private void evaluate(GuardedDeployment dep) {
        String rulesCsv = dep.getMatchedRules();
        if (rulesCsv == null || rulesCsv.isBlank()) {
            guardedDeployService.rollback(dep.getDeploymentId(),
                    "canary-health: no matched rule baseline available; refusing time-only auto-promotion");
            return;
        }

        Instant canaryStart = dep.getCanaryStartedAt() != null ? dep.getCanaryStartedAt() : dep.getCreatedAt();
        Instant preStart = canaryStart.minus(bakeTime);
        Instant now = Instant.now();

        long preCount = 0;
        long postCount = 0;
        for (String rule : rulesCsv.split(",")) {
            rule = rule.trim();
            if (rule.isEmpty()) continue;
            String canaryHost = dep.getCanaryHost();
            if (canaryHost == null || canaryHost.isBlank()) {
                guardedDeployService.rollback(dep.getDeploymentId(), "canary-health: missing canary host identity");
                return;
            }
            preCount += incidentRepository.countByEvent_HostnameAndMatchedRulesContainingAndCreatedAtBetween(canaryHost, rule, preStart, canaryStart);
            postCount += incidentRepository.countByEvent_HostnameAndMatchedRulesContainingAndCreatedAtBetween(canaryHost, rule, canaryStart, now);
        }

        if (preCount == 0) {
            guardedDeployService.rollback(dep.getDeploymentId(),
                    "canary-health: no pre-canary baseline incidents for rule(s) [" + rulesCsv + "] -- refusing time-only auto-promotion");
            return;
        }

        if (postCount < preCount) {
            guardedDeployService.promote(dep.getDeploymentId());
            auditLogger.log(dep.getIncidentId(), "CANARY_HEALTH_PROMOTE",
                    "deployment=" + dep.getDeploymentId() + " rules=[" + rulesCsv + "]"
                            + " pre=" + preCount + " post=" + postCount + " (recurrence improved)");
        } else {
            guardedDeployService.rollback(dep.getDeploymentId(),
                    "canary-health: incident rate for rule(s) [" + rulesCsv
                            + "] did not improve (pre=" + preCount + " post=" + postCount + ")");
        }
    }

}
