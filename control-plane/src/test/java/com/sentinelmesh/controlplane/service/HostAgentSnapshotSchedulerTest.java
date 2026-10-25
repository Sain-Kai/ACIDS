package com.sentinelmesh.controlplane.service;

import com.sentinelmesh.controlplane.client.HostAgentClient;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.mockito.Mockito.*;

class HostAgentSnapshotSchedulerTest {
    @Test
    void disabledReclaimDoesNotContactHostAgent() {
        HostAgentClient client = mock(HostAgentClient.class);

        new HostAgentSnapshotScheduler(client, false).snapshotKnownHosts();

        verifyNoInteractions(client);
    }

    @Test
    void enabledReclaimSnapshotsKnownHosts() {
        HostAgentClient client = mock(HostAgentClient.class);
        when(client.hosts()).thenReturn(List.of("host-a"));
        when(client.snapshot("host-a")).thenReturn(true);

        new HostAgentSnapshotScheduler(client, true).snapshotKnownHosts();

        verify(client).hosts();
        verify(client).snapshot("host-a");
        verifyNoMoreInteractions(client);
    }
}
