package com.sentinelmesh.controlplane.repository;

import com.sentinelmesh.controlplane.model.GuardedDeployment;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface GuardedDeploymentRepository extends JpaRepository<GuardedDeployment, String> {

    /** Used by CanaryPromotionScheduler to find deployments still baking. */
    List<GuardedDeployment> findByStage(GuardedDeployment.Stage stage);
}
