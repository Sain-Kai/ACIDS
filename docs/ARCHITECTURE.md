# SentinelMesh Architecture

## Design principle

Detection is deterministic and fast. Recovery is autonomous and thorough.
LLM reasoning is powerful but slow and non-deterministic, so it is kept
strictly out of the path between "event observed" and "containment action
taken." It is used afterward, where its strengths (synthesis, explanation,
proposing a fix) matter more than its weaknesses (latency, occasional error)
hurt.

## Hot path (P0)

```
eBPF / Falco -> normalize -> feature extraction -> deterministic rule engine
             -> risk score -> immediate response -> incident record
```

Each stage is a plain function/service call, not an LLM call. Target latency
is milliseconds (in-process rule evaluation) to low hundreds of milliseconds
(anything that shells out to iptables/cgroups for containment). This lives in
`detection-engine/` (Go, chosen for low-overhead concurrency and because it's
the ecosystem Falco itself and most eBPF tooling live in).

Event contract: every ingest source converts its raw event into the schema at
`common/schema/event.schema.json` before it touches the rule engine. That
schema is the one contract every other service (control-plane,
llm-orchestration) is written against.

## Reclaim path (P1)

Triggered when evidence of compromise arrives that didn't go through a clean
"detect -> immediate response" cycle (e.g. a signal from the hot path that
crosses a "likely already compromised" threshold, or an external signal —
EDR alert, log anomaly, manual trigger).

```
COMPROMISE DETECTED -> CONTAIN -> IDENTIFY -> TERMINATE -> QUARANTINE
                     -> REVOKE/ROTATE -> RESTORE -> VERIFY -> RECOVER
```

This state machine lives in `control-plane/` (`ReclaimProtocolService`),
not in the Go hot-path service — by the time reclaim runs, the emergency
brake (immediate containment) has typically already been pulled by the
hot path, and what's left is orchestration across systems that don't need
sub-millisecond latency: credential stores, backup/restore, forensic
snapshotting.

Every step that touches the protected host does so through `host-agent/`
— a small daemon running on that specific host, called over HTTP by
hostname (`HostAgentClient`). `ReclaimProtocolService` itself never runs a
system command or touches a filesystem directly:

```
control-plane (ReclaimProtocolService)
        |
        |  HTTP, by hostname, X-SentinelMesh-Api-Key
        v
host-agent (on the affected host)
   kill / lock-account / quarantine / isolate+lift
   / snapshot+restore / persistence-scan / sandbox-analyze
```

This is the difference between a single-host dev setup and something that
works across a real fleet: control-plane doesn't need to share a
filesystem or process namespace with whatever it's protecting, it just
needs network reachability to that host's agent. "Which host" comes from
`Host.Hostname`/`Host.IP`, stamped onto every event by detection-engine
itself (`detectHostname`/`detectLocalIP` in `normalize.go`) rather than
trusted from the event source — Falco/eBPF report what happened on a box,
not what the box's own identity is.

A host-agent call failing, or a host being unreachable, is logged and
treated as "nothing to do for this step" rather than an unhandled
exception — see `HostAgentClient`'s own class comment. One bad host
shouldn't abort reclaim for the rest of an otherwise-healthy sequence.

## Post-containment (LLM layer)

Once an incident is contained, `control-plane` hands it to
`llm-orchestration/` (Python, using locally-served models via Ollama):

```
RCA agent -> Patch agent -> Security Judge -> (approved) guarded deploy
```

- **RCA agent** builds a root-cause report from the incident's event(s),
  matched rule(s), and actions taken.
- **Patch agent** proposes a concrete fix (new detection rule, config
  change, code patch) — it does not apply anything.
- **Security Judge** reviews the proposal against the RCA and a policy
  checklist and returns APPROVE/REJECT with rationale. Nothing reaches
  deployment without an explicit approval here.

Deeper behavioral analysis of a suspicious artifact (when the deterministic
engine flags something but can't classify it confidently) happens inside
`sandbox/` — an isolated, network-disabled container — before RCA runs, so
the LLM layer has real dynamic-analysis output to reason over instead of
just static signals. This runs via the affected host's own host-agent
(`/v1/sandbox-analyze`), not in control-plane, since the quarantined
artifact lives on that host, not necessarily wherever control-plane runs.

## Auditability

Every autonomous action (containment action, reclaim-protocol state
transition, LLM-proposed patch, judge verdict, deploy) is written through
`control-plane`'s `AuditLogger` as an append-only, timestamped record tied
to the incident ID. Nothing autonomous happens off the audit trail.

## Service-to-service authentication

Four hops cross a service boundary, each authenticated with a
shared-secret header (`X-SentinelMesh-Api-Key`):

```
detection-engine  --incident-->        control-plane      (key: "detection-engine")
llm-orchestration --deploy-->          control-plane      (key: "llm-orchestration")
control-plane     --analyze-->         llm-orchestration  (key: control-plane's own)
control-plane     --kill/isolate/etc-> host-agent          (key: control-plane's own,
                                                              shared across every host)
```

Every receiving service fails closed: control-plane denies every request
if its key config is empty/malformed, and both llm-orchestration and
host-agent refuse to start without `SENTINELMESH_API_KEY` set.
`/actuator/health` (control-plane) and `/healthz` (host-agent, llm-orchestration)
are the only unauthenticated endpoints, and control-plane's never returns
component detail.

control-plane uses **one shared key for every host-agent instance** in
this deployment, not per-host keys — simpler, but it means a compromised key
affects every protected host at once rather than one. Noted as a scoping
decision, not an oversight: per-host keys are straightforward to add
(`HostAgentClient` would need a hostname → key lookup instead of one
constant) if a deployment's trust model needs it.

This is proportionate for a private-network service-to-service API. It is
not a user-facing auth model — anything with human operators (e.g. a
console for approving `RECLAIM_NEEDS_REVIEW` incidents) needs real
identity, RBAC, and audit-by-user, which don't exist yet.

## host-agent: validate first, execute second

Every host-agent action takes input from a network caller (control-plane)
and feeds it to a shell command or the filesystem — the textbook shape for
an injection vulnerability if input reached `exec.Command` unchecked. The
rule followed throughout `host-agent/internal/actions`: validation
(`internal/validate`) runs *before* anything touches a command or a path,
and it rejects rather than sanitizes-and-continues. A few examples of what
that means concretely:

- **Kill** requires both a PID and the exe path the triggering event
  recorded, and re-checks `/proc/<pid>/exe` against it before signaling —
  a PID from a historical event may have exited and been reused by an
  unrelated process by the time reclaim runs; killing by number alone
  would eventually kill something innocent.
- **IPs** must parse as real, non-loopback, non-unspecified IPv4 — nothing
  that could end up as an extra iptables flag, and nothing that would
  firewall the host off from itself.
- **Usernames** are checked against a protected/system-account denylist
  (`root`, `daemon`, `systemd-*`, ...) — this applies even to an
  authenticated, otherwise-legitimate request; there's no override.
- **Quarantine targets** can't be `/`, `/etc`, `/proc`, `/boot`, inside the
  quarantine directory itself, or a symlink/directory (a moved symlink's
  chmod would follow it and strip permissions from the *target*, not the
  link).

None of this is a substitute for network-level controls (host-agent should
still only be reachable from control-plane, ideally enforced at the
network layer too) — it's the layer that holds even if that control
fails, or if control-plane itself is ever compromised and starts sending
malicious-but-authenticated requests.

## Canary promotion

After the Security Judge approves a patch, `GuardedDeployService` stages
it and enters a canary window. When the window elapses,
`CanaryPromotionScheduler` decides promote vs. roll back:

1. If the deployment carries the rule name(s) it targets *and* those rules
   fired at least once in an equal-length window before the canary, compare
   pre- vs. during-canary incident counts for those rules. Fewer → promote.
   Same or more → roll back (the patch didn't reduce recurrence of the
   problem it was meant to address).
2. Otherwise (no rule reference, or no baseline to compare against) →
   promote on elapsed time alone.

Every outcome is written to the audit trail with which path was taken.
This is deliberately a single, narrow signal — it answers "did the
targeted recurrence go down?", not "is the detection posture better?", and
it is not a substitute for real canary metrics (error rate, latency,
false-positive rate) once a metrics pipeline exists.

## Runtime-defense increment: 69% functional / 40% production target

The current implementation increment makes the following paths concrete:

1. **P0 hot path:** source ingestion -> normalization -> deterministic rule evaluation -> noisy-OR risk aggregation -> immediate local response. Incident forwarding is asynchronous and bounded so control-plane/LLM latency cannot hold the detector loop.
2. **Reclaim trigger:** reclaim-threshold events immediately attempt local process kill, host isolation, and artifact quarantine before asynchronous incident delivery.
3. **Missed attack:** control-plane can receive an external compromise signal and also periodically interrogate active host-agents for persistence indicators. Positive independent evidence creates an autonomous reclaim incident.
4. **Recovery durability:** reclaim state is checkpointed before each privileged stage and `ReclaimRecoveryScheduler` resumes interrupted `RECLAIM_IN_PROGRESS` incidents after process restart.
5. **Post-containment AI:** RCA/patch/judge runs on a bounded asynchronous executor and is never required to make the real-time containment decision.
6. **Normalization depth:** Falco process, network, file, syscall, severity, tag, and container fields are mapped into the common event representation; eBPF events carry explicit syscall types.
7. **Agent hardening:** privileged HTTP requests use constant-time API-key comparison, bounded request bodies, strict JSON fields, and server-side timeouts.

### Deployment prerequisites, not application stubs

The application paths are implemented end-to-end. Deployment still requires environment-specific prerequisites: native eBPF objects must be generated against the target kernel; each protected host must have an explicitly registered and authenticated host-agent endpoint; the optional external credential connector must be configured when cloud/service identities need revocation; and production sandbox execution must use the selected hardened runtime (the reference stack defaults to gVisor `runsc`). These are deployment bindings, not deferred application control-flow stubs.
