package com.sentinelmesh.controlplane.service;

import com.sentinelmesh.controlplane.client.HostAgentClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Periodic driver for every known host's snapshots -- without this
 * running, ReclaimProtocolService's restore() step always finds "no
 * snapshot available" and silently skips restoration, regardless of how
 * well host-agent's own snapshot/restore logic works.
 *
 * The host registry is the source of truth. Every registered host is
 * periodically snapshotted so reclaim has a usable pre-incident restore
 * point even if the host had been quiet before compromise.
 */
@Component
public class HostAgentSnapshotScheduler {

    private static final Logger log = LoggerFactory.getLogger(HostAgentSnapshotScheduler.class);

    private final HostAgentClient hostAgentClient;

    public HostAgentSnapshotScheduler(HostAgentClient hostAgentClient) {
        this.hostAgentClient = hostAgentClient;
    }

    @Scheduled(
            fixedRateString = "${sentinelmesh.reclaim.snapshot-interval-minutes}",
            timeUnit = TimeUnit.MINUTES
    )
    public void snapshotKnownHosts() {
        List<String> hosts = hostAgentClient.hosts();
        for (String host : hosts) {
            if (host == null || host.isBlank()) continue;
            boolean ok = hostAgentClient.snapshot(host);
            if (ok) {
                log.info("triggered snapshot on host={}", host);
            } else {
                log.warn("snapshot request failed for host={}", host);
            }
        }
    }
}
