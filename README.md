# SENTINELMESH

Autonomous real-time runtime defense platform with a deterministic P0 hot path and a fail-closed P1 system-reclamation path.

## End-to-end flow

```text
Falco JSON HTTP / eBPF
      |
      v
  normalization
      |
      v
 deterministic rules + runtime policy
      |
      +-----------------------------+
      |                             |
      v                             v
 benign telemetry              immediate local response
                                |  kill process
                                |  block network
                                |  isolate host
                                |  quarantine file
                                v
                          async incident outbox
                                |
                                v
                           control-plane
                                |
                 +--------------+---------------+
                 |                              |
           normal incident                compromise evidence
                 |                              |
                 v                              v
            sandbox                       RECLAIM PROTOCOL
                 |                    contain -> identify -> terminate
                 v                    -> quarantine -> revoke/rotate
            RCA / Patch               -> restore -> verify -> recover
                 |
                 v
          Security Judge
                 |
          guarded canary
                 |
          promote/rollback
                 |
                 v
       signed runtime policy
                 |
                 v
       host-agent + detector
```

LLMs never sit between telemetry arrival and immediate containment. They are downstream-only.

## Repository

- `detection-engine/` — Go hot-path engine; Falco/eBPF ingestion, normalization, deterministic scoring, local containment, signed runtime policy.
- `host-agent/` — per-host privileged daemon; kill, isolate/lift, quarantine, account lock, snapshots, restore, persistence verification, sandbox execution, signed policy apply/rollback.
- `control-plane/` — Spring Boot incident store, authenticated service APIs, reclaim state machine, host registry, guarded deployment, audit hash-chain, Postgres/Flyway support.
- `llm-orchestration/` — Flask/Gunicorn RCA → patch manifest → security judge; local Ollama only.
- `sandbox/` — isolated analysis image and bounded analysis script.
- `common/schema/` — normalized event schema.
- `deploy/` — production and protected-host Compose stacks, environment template, Prometheus config, bootstrap/doctor scripts.
- `scripts/` — native eBPF build, configuration validation, deterministic E2E test, release checks.

## Security invariants

1. The P0 decision path contains no network/model dependency.
2. High-confidence reclaim decisions execute local containment before forwarding an incident.
3. Host-agent calls are authenticated and fail closed.
4. Reclaim does not auto-recover after failed isolation, restore, verification, or credential-revocation steps.
5. Runtime policies are HMAC-signed and versioned; host agents reject tampered or out-of-order updates.
6. Guarded deployment canary failures trigger rollback; rollback failure enters `FAILED_NEEDS_REVIEW`.
7. Every autonomous reclaim/deployment transition is written to the durable audit hash chain.
8. Suspicious artifacts are executed only in the dedicated sandbox path, never by the LLM service itself.
9. Model-generated policy changes are never promoted on elapsed time alone; a measurable canary baseline must improve or the change rolls back.

## Production deployment

Target environment: Linux host with a BTF-enabled kernel, Falco with HTTP output enabled, Docker Engine/Compose, Go/clang/bpftool for the native probe build, and a reachable Ollama service hosting the configured models.

### 1. Bootstrap

```bash
cd SentinelMesh
./deploy/doctor.sh
./deploy/bootstrap.sh
```

`bootstrap.sh` creates `deploy/.env` from the template, generates cryptographic secrets for missing placeholders, generates the target-kernel eBPF bindings, and validates the production Compose configuration.

### 2. Start the reference stack

```bash
docker compose --env-file deploy/.env \
  -f deploy/docker-compose.prod.yml \
  up -d --build
```

The production stack contains Falco 0.45.0 with Modern eBPF, Postgres, control-plane, LLM orchestration, detector, host-agent, sandbox image, and host-local Prometheus. The supplied Compose stack is intentionally privileged because runtime containment and kernel telemetry operate on the protected host.

### 3. Verify

```bash
curl -fsS http://127.0.0.1:8080/actuator/health
curl -fsS http://127.0.0.1:2112/healthz
curl -fsS http://127.0.0.1:9090/healthz
```

Then run:

```bash
make release-check
make e2e
# On the deployment host, after the stack is running:
make e2e-stack
./scripts/verify-ollama.sh
```

When a fail-closed reclaim stops in `RECLAIM_NEEDS_REVIEW`, a security-automation principal must explicitly approve continuation with `POST /incidents/{id}/reclaim/approve`; the workflow resumes from its persisted next action.

`make e2e` is deliberately non-destructive: it runs the detector in dry-run mode against a Falco-shaped reverse-shell event and checks the real normalization/detection/incident transport path.

## Native eBPF build

The checked-in repository intentionally does not contain kernel-specific `vmlinux.h` or generated `bpf2go` object bindings. On each deployment/build host:

```bash
./scripts/build-native.sh
```

The script requires Linux, `clang`, `bpftool`, kernel BTF, and network access for the Go module download. The generated bindings are then included in the detector build context.

## Operational model

The system is designed for one detector + one host-agent per protected host, with the control-plane holding durable incident and deployment state. `SENTINELMESH_HOST_REGISTRY` maps event hostnames to authenticated host-agent endpoints.

For dense multi-tenant/container workloads, replace host-level iptables isolation with a workload-specific network policy / network-namespace actuator. The current implementation intentionally treats the protected host as the security boundary.

## Verification

The repository includes a release gate covering configuration invariants, native/non-native Go paths, host-agent tests, LLM safety tests, deterministic detector E2E, Falco rule validation, Docker Compose rendering, and target-kernel eBPF generation. This development environment does not have Docker, Maven, Go 1.25, or a BTF-enabled production kernel, so the privileged target-host checks must be executed on the actual deployment/build host. The scripts deliberately fail closed when those prerequisites are absent.
