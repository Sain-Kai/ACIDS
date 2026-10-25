# SentinelMesh 1.0.0 — End-to-End Release Manifest

This tree is the complete application/deployment implementation for SentinelMesh's stated runtime-defense workflow.

## Runtime path

Falco HTTP / native eBPF -> normalization -> deterministic rule engine -> synchronous local containment -> durable asynchronous incident outbox -> control-plane -> checkpointed reclaim -> sandbox analysis -> RCA -> constrained patch proposal -> deterministic security judge -> guarded canary -> security-automation promotion/rollback -> signed runtime policy distribution.

## Production profiles

- `deploy/docker-compose.prod.yml`: fleet/reference profile; control-plane, Postgres, and LLM services use an internal container network while Falco, detector, host-agent, and Prometheus use host networking where required for kernel/host access.
- `deploy/docker-compose.protected-host.yml`: single protected Linux host profile with Postgres and management services bound to loopback.

## Non-optional safety properties

- No model/cloud/API dependency exists between telemetry observation and local P0 containment.
- High-confidence reclaim crosses the local emergency-containment path before incident forwarding.
- Host-agent privileged calls are authenticated and verified; reclaim fails closed on unreachable/failed checkpoints.
- Reclaim state is persisted before each privileged step and resumed after restart.
- Signed runtime policies are monotonic and validated before activation.
- Model-generated policy changes are restricted to defensive block/pattern manifests and cannot directly promote or rollback deployments.
- Sandbox analysis defaults to gVisor `runsc` in production deployment configuration.
- Audit records are hash-chained and fsync'd.

## Acceptance gate

Run `scripts/release-check.sh` on a build machine. For the native production build, the machine must provide Go 1.25+, clang, bpftool, Linux kernel BTF, Docker Engine/Compose, and the configured sandbox runtime. The gate intentionally refuses to call a degraded environment production-ready.

The present source-validation environment lacks Docker, Maven, Go 1.25, and the target kernel/BTF, so those privileged/runtime acceptance checks cannot honestly be marked passed here.
