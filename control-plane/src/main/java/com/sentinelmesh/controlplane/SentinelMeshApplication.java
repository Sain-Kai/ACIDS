package com.sentinelmesh.controlplane;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling // drives HostAgentSnapshotScheduler and CanaryPromotionScheduler
public class SentinelMeshApplication {
    public static void main(String[] args) {
        SpringApplication.run(SentinelMeshApplication.class, args);
    }
}
