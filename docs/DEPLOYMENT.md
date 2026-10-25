# SentinelMesh production deployment

## Prerequisites

- Linux kernel 5.8+ with BTF available at `/sys/kernel/btf/vmlinux`.
- Docker Engine + Compose plugin.
- `go`, `clang`, `bpftool` on the build host.
- Falco installed/configured with SentinelMesh rules and HTTP output enabled.
- Ollama reachable from the LLM service, with the selected RCA/patch/judge models present.
- A private management path from control-plane to each host-agent.

## First deployment

```bash
./deploy/doctor.sh
./deploy/bootstrap.sh
docker compose --env-file deploy/.env -f deploy/docker-compose.prod.yml up -d --build
./scripts/verify-ollama.sh
```

`bootstrap.sh` does not overwrite non-placeholder secrets. Keep `deploy/.env` mode 0600/root-only and preferably replace environment secrets with the platform's secret store in the final infrastructure.

## Falco


Current Falco releases use HTTP output for this integration; the production stack pins Falco 0.45.0.

The detector treats Falco as telemetry, not as the final decision maker: the normalized Falco event is re-evaluated through SentinelMesh's deterministic rule engine.

## Host root mapping

The detector and host-agent containers mount the protected host at `/hostfs`. Logical paths emitted by telemetry remain `/etc/...`, `/home/...`, etc.; local actions map them into `/hostfs/...`. This keeps the incident API host-agnostic while preserving correct filesystem targeting from a container.

## Policy deployment

Runtime policy is HMAC-signed. The control-plane creates a new version from a constrained patch manifest, applies it to a canary host through the host-agent, and only promotes after the canary gate passes. Host-agent rejects unsigned updates and rejects a forward apply that does not increase the policy version.

## Reclaim semantics

A reclaim workflow remains isolated until all required checkpoints succeed. Failures in containment, termination, quarantine, credential revocation, restore, persistence verification, or recovery move the incident to `RECLAIM_NEEDS_REVIEW` and leave network isolation in place.

## Sandbox

Build `sandbox/Dockerfile.sandbox` as `sentinelmesh-sandbox:latest`. Production bootstrap defaults `SANDBOX_RUNTIME=runsc` and requires gVisor to be installed; the host-agent launches the analysis container with no network, read-only root, dropped capabilities, no-new-privileges, bounded memory/CPU/PIDs, and a non-root execution user. `runc` remains available only as an explicitly selected lab/development fallback. For stronger isolation, use the same host-agent contract with a Firecracker-backed implementation.

## Backups and audit

Postgres is the control-plane system of record. Host snapshot volumes are per-host. The audit trail uses a SHA-256 hash chain and `fsync` on each append. Export the audit file to immutable remote retention/WORM storage in production; the local chain provides tamper evidence but is not itself a remote immutable archive.
