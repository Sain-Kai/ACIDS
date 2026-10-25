# SentinelMesh operations runbook

## P0 detection

Observe detector `/metrics` and logs. A non-benign verdict is contained locally before its incident is delivered upstream. The control-plane is not on the P0 critical path.

## P1 reclaim

When an incident enters `RECLAIM_IN_PROGRESS`:

1. Confirm host identity and host-agent registration.
2. Verify isolation and triggering-process termination.
3. Review the correlated-event blast radius.
4. Confirm artifact quarantine.
5. Confirm local account lock and external credential connector status when configured.
6. Confirm restore from a pre-incident snapshot.
7. Confirm persistence scan is clean.
8. Only then is isolation lifted.

Any failed step leaves the host contained and moves the incident to `RECLAIM_NEEDS_REVIEW`.

## Manual rollback

Use the authenticated `/deploy/{deploymentId}/rollback` endpoint. The control-plane attempts the exact previous signed policy on every target host. If any rollback fails, the deployment remains `FAILED_NEEDS_REVIEW`.

## Key rotation

Rotate service API keys and the policy-signing key through your secret-management system. Restart services only after all consumers have the new value. Policy signatures use HMAC-SHA256; a mismatched signing key deliberately causes runtime updates to be rejected.

## Health checks

- Control plane: `GET /actuator/health`
- Detector: `GET /healthz`
- Host agent: `GET /healthz`
- LLM orchestration: `GET /healthz`
- Prometheus: `http://127.0.0.1:9091`

## Incident forensics

Preserve the incident record, normalized event, raw payload, quarantine path, sandbox report, audit hash-chain entry, and host snapshots. Do not delete the quarantine volume until the incident has passed retention and evidence review.
