# SentinelMesh implementation status

The repository contains the complete intended application/control/data flow: deterministic telemetry detection, immediate local containment, durable incident spooling, independent compromise detection, checkpointed fail-closed reclaim, host-level reclamation, local hash-chained action audit, sandbox analysis, downstream LLM RCA/patch/judge, signed runtime policy distribution, guarded canary deployment, rollback, persistence, metrics, and deployment automation.

## Locally verified in this build environment

- `detection-engine`: Go tests/vet/build passed before the final Go 1.25 toolchain alignment; the current source requires Go 1.25 because `cilium/ebpf v0.22.0` now declares that minimum.
- `host-agent`: Go tests/vet/build passed before the final Go 1.25 toolchain alignment.
- Python syntax checks for LLM orchestration
- JSON/YAML/XML validation and shell syntax checks
- detector dry-run E2E path

## Target-host validation required before production change approval

The following need the real deployment environment and cannot be truthfully marked passed from a source-only build environment:

- generate/load native eBPF bindings against the target kernel BTF;
- validate Falco rules with the installed Falco binary and exercise real Falco JSON HTTP events;
- build/run the privileged Compose stack;
- execute a controlled containment/reclaim drill on a disposable host;
- verify Postgres/Flyway/Spring startup and integration tests;
- verify Ollama models and a real canary deployment;
- configure an immutable remote audit sink and the organization's secrets/identity controls.

These are environment acceptance tests, not unimplemented application logic.
