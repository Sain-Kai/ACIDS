package com.sentinelmesh.controlplane.repository;

import com.sentinelmesh.controlplane.model.SecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;

public interface SecurityEventRepository extends JpaRepository<SecurityEvent, String> {

    /** Used by ReclaimProtocolService's identify() step to build a blast
     *  radius: every other event seen on the same host within a window
     *  around the triggering incident. */
    List<SecurityEvent> findByHostnameAndTimestampBetween(String hostname, Instant start, Instant end);

    /** Used by HostAgentSnapshotScheduler to find which hosts are
     *  currently active (and therefore have a reachable host-agent worth
     *  snapshotting) -- hosts seen in at least one event since `since`.
     *  There's no separate host registry in this deployment; this is the
     *  closest proxy for "known hosts" available from what's already
     *  persisted. */
    List<String> findDistinctHostnameByTimestampAfter(Instant since);
}
