# SentinelMesh host-agent

A small HTTP daemon that runs on every protected host and performs the
privileged actions control-plane needs on that specific host: kill a
process, lock a local account, quarantine a file, isolate/lift network
access (iptables), snapshot/restore files, scan for persistence
indicators, and run a quarantined artifact through sandbox analysis.

## Why this exists

Earlier, control-plane did all of this itself — directly running `iptables`,
`usermod`, filesystem snapshots, etc. That only works when control-plane
happens to share a filesystem and process namespace with the thing it's
protecting, which is true on a single-host dev laptop and false for any real
fleet. host-agent is what makes `ReclaimProtocolService` actually work
across multiple hosts: control-plane calls `http://<hostname>:9090/v1/...`
instead of executing anything locally.

detection-engine's hot-path containment (kill/block/isolate/quarantine in
`internal/response/actions.go`) is **not** routed through host-agent — it
runs locally, by design, because it's on the same host already and P0
latency requirements rule out an extra network hop for the fast path.
host-agent exists for the *reclaim* protocol's slower, cross-cutting
actions, not the hot path.

## Security posture

Every endpoint except `/healthz` requires `X-SentinelMesh-Api-Key`,
checked against `SENTINELMESH_API_KEY` — same shared-secret pattern as the
other three services, and the agent refuses to start without that env var
set (fail closed). Every input is validated in `internal/validate` before
it reaches a shell command or the filesystem: IPs must be real non-loopback
IPv4, usernames are checked against a system/protected-account denylist,
quarantine targets can't be `/`, `/etc`, `/proc`, or inside the quarantine
directory itself, and so on. See that package's own tests for the exact
rules.

This is still a genuinely dangerous service to expose: it can kill
processes, firewall a host off from everything but SSH, and lock accounts,
all by design. Run it only on a private network reachable by control-plane,
behind the real secret (not the `CHANGE-ME` dev placeholder), and ideally
also behind host-level access control (e.g. only control-plane's IP
allowed to reach port 9090).

## Running

```
go build -o agent ./cmd/agent
SENTINELMESH_API_KEY=... ./agent     # listens on :9090 by default
```

Needs root (or the specific capabilities below) to do anything beyond
return errors: `CAP_NET_ADMIN`+`CAP_NET_RAW` for iptables, `CAP_KILL` for
process termination, and `CAP_CHOWN`/root for `usermod`.

See `Dockerfile` for a container build, and
`deploy/docker-compose.yml`'s commented-out `host-agent` service in the
main repo for the privileges a containerized run needs.

## Endpoints

| Method | Path | Body | Purpose |
|---|---|---|---|
| GET | `/healthz` | — | No auth. Liveness only. |
| POST | `/v1/kill` | `{"targets":[{"pid":1234,"exe":"/tmp/x"}]}` | Kill matching processes |
| POST | `/v1/account/lock` | `{"username":"www-data"}` | Lock a local account + kill its processes |
| POST | `/v1/quarantine` | `{"path":"/tmp/x","event_id":"evt-1"}` | Move + chmod-0 a file |
| POST | `/v1/network/isolate` | `{"ip":"10.0.0.5"}` | Firewall the host off except SSH |
| POST | `/v1/network/lift` | `{"ip":"10.0.0.5"}` | Reverse isolate |
| POST | `/v1/snapshot` | — | Snapshot the configured watch paths now; returns a snapshot id |
| POST | `/v1/restore` | `{"path":"/etc/x","before":"2026-01-01T00:00:00Z"}` | Restore from the latest snapshot before that time |
| POST | `/v1/persistence-scan` | `{"since":"2026-01-01T00:00:00Z"}` | Files modified since, under the configured watch paths |
| POST | `/v1/sandbox-analyze` | `{"quarantine_path":"/var/lib/sentinelmesh/quarantine/evt-1_x"}` | Static + bounded-dynamic analysis of a quarantined artifact (needs the `sentinelmesh-sandbox` Docker image built locally, and Docker itself) |

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `LISTEN_ADDR` | `:9090` | |
| `SENTINELMESH_API_KEY` | *(required)* | |
| `QUARANTINE_DIR` | `/var/lib/sentinelmesh/quarantine` | |
| `SANDBOX_STAGING_DIR` | `/var/lib/sentinelmesh/sandbox-staging` | disposable readable copies for sandbox analysis |
| `SNAPSHOT_DIR` | `/var/lib/sentinelmesh/snapshots` | |
| `SNAPSHOT_PATHS` | `/etc,/home/*/.ssh,/root/.ssh` | comma-separated, glob patterns allowed |
| `SNAPSHOT_KEEP` | `24` | newest N snapshots retained; `0` keeps all |
| `PERSISTENCE_CHECK_PATHS` | cron/systemd/ssh paths | comma-separated, glob patterns allowed |

Nothing schedules periodic snapshots inside host-agent itself — that lives
in control-plane's `SnapshotScheduler`, calling `POST /v1/snapshot` on each
known host on an interval. host-agent's own job is to execute one snapshot
when asked, not to decide when.

## Known limitations

- **No automatic snapshot scheduling** (see above) — control-plane must
  call `/v1/snapshot` periodically per host for `/v1/restore` to ever
  have something to restore from.
- **No rate limiting or request size caps.**
- **`/v1/kill` matches on binary name, not a cryptographic identity** — see
  `internal/actions/kill.go`'s comment on `sameBinary` for why (a PID from
  a historical event may have been reused by an unrelated process by the
  time reclaim runs) and its limits (a same-named replacement binary would
  still match).
- **Not validated against a real target environment** — like the rest of
  this project's Go code, this has been syntax-checked and unit-tested
  with faked system calls, but the actual `iptables`/`usermod`/`cp`
  invocations haven't run for real. CI (`.github/workflows/ci.yml`) is the
  first real build and test run.
