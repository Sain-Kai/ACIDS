package com.sentinelmesh.controlplane.repository;

import com.sentinelmesh.controlplane.model.Incident;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface IncidentRepository extends JpaRepository<Incident, String> {
    long countByMatchedRulesContainingAndCreatedAtBetween(String ruleNameFragment, Instant start, Instant end);

    long countByEvent_HostnameAndMatchedRulesContainingAndCreatedAtBetween(String hostname, String ruleNameFragment, Instant start, Instant end);

    Optional<Incident> findFirstByEventHostnameAndStatusInOrderByCreatedAtDesc(String hostname, List<Incident.Status> statuses);

    List<Incident> findByStatusOrderByCreatedAtAsc(Incident.Status status);
    Optional<Incident> findByIdempotencyKey(String idempotencyKey);
    List<Incident> findTop100ByOrderByCreatedAtDesc();
}
