# SentinelMesh release verification

Release target: end-to-end functional implementation with deterministic P0 detection, immediate containment, durable P1 reclaim, downstream LLM analysis, signed policy rollout, canary rollback, persistent state, and deployable Linux Compose stacks.

## Verified in the source-only build environment

- configuration invariants: PASS
- JSON/YAML/XML parsing: PASS
- Python syntax: PASS
- shell syntax: PASS
- deterministic detector E2E harness: PASS before final Go 1.25 toolchain alignment
- host-agent Go tests/vet/build: PASS before final Go 1.25 toolchain alignment
- detector Go tests/vet/build: PASS before final Go 1.25 toolchain alignment
- LLM deployment gate: PASS (approved model output is blocked while reclaim is awaiting review/in progress)

## Required on the deployment/build host

- Go 1.25+ for the current `github.com/cilium/ebpf v0.22.0` dependency.
- Linux kernel with BTF exposed at `/sys/kernel/btf/vmlinux`.
- `clang` + `bpftool` for target-kernel eBPF generation.
- Docker Engine + Compose.
- gVisor `runsc` (or an explicitly selected lab runtime) for sandbox execution.
- PostgreSQL availability for the production profile.
- Ollama and the configured RCA/patch/judge models.
- A controlled disposable-host containment/reclaim drill before production approval.

The release scripts deliberately fail closed on missing target prerequisites rather than silently deploying a degraded security control.
