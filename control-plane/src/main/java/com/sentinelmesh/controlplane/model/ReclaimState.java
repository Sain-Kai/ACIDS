package com.sentinelmesh.controlplane.model;

/**
 * Steps of the P1 reclaim protocol (see ReclaimProtocolService). Lives in
 * the model package -- not nested in the service class -- so the Incident
 * entity doesn't have to depend on the service layer to reference it.
 */
public enum ReclaimState {
    CONTAIN, IDENTIFY, TERMINATE, QUARANTINE, FORENSIC_SNAPSHOT, REVOKE_ROTATE, RESTORE, VERIFY, RECOVER, DONE
}
